//! Presentation of native enrollment material. Never log or persist its contents.
use crate::auth::MessagePrinter;
use crate::i18n::tr;
use crate::unix_proto::EnrollmentPresentation;
use base64::{engine::general_purpose::STANDARD, Engine};
use image::{ImageFormat, ImageReader, Limits};
use std::io::Cursor;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_PNG_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_QR_SOURCE_BYTES: usize = MAX_PNG_BYTES.div_ceil(3) * 4 + 22;
const MAX_QR_PAYLOAD_BYTES: usize = 2048;

// Only the configured issuer may supply images; presentation never follows links.
fn image_url(source: &str, origin: &str) -> Result<reqwest::Url, ()> {
    if source.len() > MAX_QR_PAYLOAD_BYTES || source.chars().any(char::is_control) {
        return Err(());
    }
    let url = reqwest::Url::parse(source).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.origin().ascii_serialization() != origin
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    Ok(url)
}

fn image_client(timeout: Duration) -> Result<reqwest::Client, ()> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout.min(Duration::from_secs(3)))
        .timeout(timeout)
        .build()
        .map_err(|_| ())
}

async fn download_image(client: &reqwest::Client, url: reqwest::Url) -> Result<String, ()> {
    let mut response = client.get(url).send().await.map_err(|_| ())?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|n| n > MAX_PNG_BYTES as u64)
    {
        return Err(());
    }
    let mut png = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if png.len().saturating_add(chunk.len()) > MAX_PNG_BYTES {
            return Err(());
        }
        png.extend_from_slice(&chunk);
    }
    // The PAM decoder validates the PNG and QR using the same limits as embedded images.
    Ok(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(png.as_slice())
    ))
}

pub(crate) async fn resolve_image(
    enrollment: &mut EnrollmentPresentation,
    origin: &str,
    request_timeout: Duration,
) {
    let Some(source) = enrollment.qr.as_deref() else {
        return;
    };
    if source.starts_with("data:image/png;base64,") {
        return;
    }
    let source = Zeroizing::new(enrollment.qr.take().unwrap_or_default());
    let Ok(url) = image_url(&source, origin) else {
        return;
    };
    let timeout = request_timeout.min(Duration::from_secs(10));
    if timeout.is_zero() {
        return;
    }
    let Ok(client) = image_client(timeout) else {
        return;
    };
    // Failure leaves the setup key available and never exposes the source URL.
    enrollment.qr = download_image(&client, url).await.ok();
}

fn decode_qr(source: &str) -> Result<Zeroizing<String>, ()> {
    if source.len() > MAX_QR_SOURCE_BYTES {
        return Err(());
    }
    let encoded = source.strip_prefix("data:image/png;base64,").ok_or(())?;
    let png = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| ())?);
    if png.len() > MAX_PNG_BYTES {
        return Err(());
    }
    let mut reader = ImageReader::with_format(Cursor::new(png.as_slice()), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(1024);
    limits.max_image_height = Some(1024);
    limits.max_alloc = Some(16 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| ())?.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        image.width() as usize,
        image.height() as usize,
        |x, y| image.get_pixel(x as u32, y as u32).0[0],
    );
    let grids = prepared.detect_grids();
    if grids.len() != 1 {
        return Err(());
    }
    let (_, payload) = grids[0].decode().map_err(|_| ())?;
    let payload = Zeroizing::new(payload);
    if payload.is_empty()
        || payload.len() > MAX_QR_PAYLOAD_BYTES
        || payload.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(payload)
}

/// Returns whether a GDM enrollment QR payload was emitted and needs cleanup.
pub(crate) fn present(
    printer: &dyn MessagePrinter,
    service: &str,
    enrollment: &EnrollmentPresentation,
) -> Result<bool, String> {
    let key = enrollment
        .setup_key
        .as_deref()
        .filter(|key| !key.is_empty() && key.len() <= 2048 && !key.chars().any(char::is_control));
    if let Some(key) = key {
        printer.print_sensitive(&format!("{}: {key}", tr("Authenticator setup key")));
    }
    let Some(source) = enrollment.qr.as_deref() else {
        return if key.is_some() {
            Ok(false)
        } else {
            Err(tr("Authenticator enrollment instructions are unavailable. Contact your administrator."))
        };
    };
    if service == "broker-interactive" {
        return if key.is_some() {
            Ok(false)
        } else {
            Err(tr("This authenticator requires QR enrollment. Sign in through a terminal or the QR-enabled greeter to enroll."))
        };
    }
    let rendered = decode_qr(source).and_then(|payload| {
        if service == "gdm-password" {
            Ok(format!(
                "[OIDC_ENROLL_QR] {}",
                STANDARD.encode(payload.as_bytes())
            ))
        } else {
            crate::auth::generate_unicode_qr(&payload).map_err(|_| ())
        }
    });
    match rendered {
        Ok(qr) => {
            printer.print_sensitive(&qr);
            printer.print_text(&tr("Scan this QR code with your authenticator app to enroll."));
            Ok(service == "gdm-password")
        }
        Err(()) if key.is_some() => {
            printer.print_text(&tr("The enrollment QR code is unavailable. Enter the setup key in your authenticator app."));
            Ok(false)
        }
        Err(()) => Err(tr("The enrollment QR code could not be read and no setup key is available. Contact your administrator.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, GrayImage, Luma};
    use std::sync::Mutex;

    const PAYLOAD: &str = "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    fn qr_image() -> GrayImage {
        let qr = qrcodegen::QrCode::encode_text(PAYLOAD, qrcodegen::QrCodeEcc::Low).unwrap();
        let size = (qr.size() + 8) as u32;
        GrayImage::from_fn(size * 4, size * 4, |x, y| {
            Luma([if qr.get_module(x as i32 / 4 - 4, y as i32 / 4 - 4) {
                0
            } else {
                255
            }])
        })
    }

    fn png_source(image: GrayImage) -> String {
        let mut output = Cursor::new(Vec::new());
        DynamicImage::ImageLuma8(image)
            .write_to(&mut output, ImageFormat::Png)
            .unwrap();
        format!(
            "data:image/png;base64,{}",
            STANDARD.encode(output.into_inner())
        )
    }

    #[derive(Default)]
    struct Printer {
        sensitive: Mutex<Vec<String>>,
        ordinary: Mutex<Vec<String>>,
    }
    impl MessagePrinter for Printer {
        fn print_text(&self, msg: &str) {
            self.ordinary.lock().unwrap().push(msg.into());
        }
        fn print_sensitive(&self, msg: &str) {
            self.sensitive.lock().unwrap().push(msg.into());
        }
        fn print_error(&self, _: &str) {
            panic!("unexpected error output");
        }
        fn prompt_echo_on(&self, _: &str) -> Option<String> {
            panic!("presentation must not prompt");
        }
        fn prompt_echo_off(&self, _: &str) -> Option<String> {
            panic!("presentation must not prompt");
        }
    }

    #[test]
    fn embedded_png_decodes_enrollment_content() {
        assert_eq!(
            decode_qr(&png_source(qr_image())).unwrap().as_str(),
            PAYLOAD
        );
    }

    #[test]
    fn terminal_qr_round_trips_without_logging_material() {
        let printer = Printer::default();
        let greeter_qr_emitted = present(
            &printer,
            "login",
            &EnrollmentPresentation {
                qr: Some(png_source(qr_image())),
                setup_key: None,
            },
        )
        .unwrap();
        assert!(!greeter_qr_emitted);
        let output = printer.sensitive.lock().unwrap();
        let lines: Vec<Vec<char>> = output[0]
            .lines()
            .map(|line| line.chars().collect())
            .collect();
        // Read the displayed half-block pixels, independently of QR generation.
        let image =
            GrayImage::from_fn(lines[0].len() as u32 * 4, lines.len() as u32 * 8, |x, y| {
                let ch = lines[y as usize / 8][x as usize / 4];
                let dark = match ch {
                    '\u{2588}' => true,
                    '\u{2580}' => y % 8 < 4,
                    '\u{2584}' => y % 8 >= 4,
                    ' ' => false,
                    _ => panic!("unexpected QR pixel"),
                };
                Luma([if dark { 0 } else { 255 }])
            });
        assert_eq!(decode_qr(&png_source(image)).unwrap().as_str(), PAYLOAD);
        assert!(!printer
            .ordinary
            .lock()
            .unwrap()
            .join("\n")
            .contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn greeter_receives_bounded_payload_without_a_file() {
        let printer = Printer::default();
        let greeter_qr_emitted = present(
            &printer,
            "gdm-password",
            &EnrollmentPresentation {
                qr: Some(png_source(qr_image())),
                setup_key: None,
            },
        )
        .unwrap();
        assert!(greeter_qr_emitted);
        let messages = printer.sensitive.lock().unwrap();
        let encoded = messages[0].strip_prefix("[OIDC_ENROLL_QR] ").unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap(), PAYLOAD.as_bytes());
    }

    #[test]
    fn invalid_image_falls_back_to_manual_setup() {
        let printer = Printer::default();
        let greeter_qr_emitted = present(
            &printer,
            "login",
            &EnrollmentPresentation {
                qr: Some("data:image/png;base64,invalid".into()),
                setup_key: Some("FIXTUREKEY".into()),
            },
        )
        .unwrap();
        assert!(!greeter_qr_emitted);
        assert!(printer.sensitive.lock().unwrap()[0].contains("FIXTUREKEY"));
        assert!(!printer
            .ordinary
            .lock()
            .unwrap()
            .join("\n")
            .contains("FIXTUREKEY"));
    }

    #[test]
    fn invalid_qr_without_key_reports_actionable_error() {
        let error = present(
            &Printer::default(),
            "login",
            &EnrollmentPresentation {
                qr: Some("data:image/png;base64,invalid".into()),
                setup_key: None,
            },
        )
        .unwrap_err();
        assert!(error.contains("no setup key"));
    }

    #[test]
    fn broker_never_receives_qr_art() {
        let printer = Printer::default();
        let greeter_qr_emitted = present(
            &printer,
            "broker-interactive",
            &EnrollmentPresentation {
                qr: Some(png_source(qr_image())),
                setup_key: Some("FIXTUREKEY".into()),
            },
        )
        .unwrap();
        assert!(!greeter_qr_emitted);
        assert_eq!(printer.sensitive.lock().unwrap().len(), 1);
        assert!(!printer.sensitive.lock().unwrap()[0].contains('\u{2588}'));
    }

    #[test]
    fn qr_only_broker_enrollment_requires_another_interface() {
        let error = present(
            &Printer::default(),
            "broker-interactive",
            &EnrollmentPresentation {
                qr: Some(png_source(qr_image())),
                setup_key: None,
            },
        )
        .unwrap_err();
        assert!(error.contains("terminal"));
    }

    #[test]
    fn rejects_oversized_and_non_qr_images() {
        assert!(decode_qr(&"x".repeat(MAX_QR_SOURCE_BYTES + 1)).is_err());
        assert!(decode_qr(&png_source(GrayImage::new(1025, 1))).is_err());
        assert!(decode_qr(&png_source(GrayImage::new(64, 64))).is_err());
    }

    #[test]
    fn rejects_multiple_qr_codes() {
        let qr = qr_image();
        let double = GrayImage::from_fn(qr.width() * 2, qr.height(), |x, y| {
            *qr.get_pixel(x % qr.width(), y)
        });
        assert!(decode_qr(&png_source(double)).is_err());
    }

    #[test]
    fn unresolved_image_urls_never_reach_generic_presentation() {
        for service in ["login", "gdm-password", "broker-interactive"] {
            for key in [None, Some("FIXTUREKEY".to_owned())] {
                let printer = Printer::default();
                let result = present(
                    &printer,
                    service,
                    &EnrollmentPresentation {
                        qr: Some("https://example.invalid/enrollment.png".into()),
                        setup_key: key.clone(),
                    },
                );
                assert_eq!(result.is_ok(), key.is_some());
                assert!(!printer
                    .sensitive
                    .lock()
                    .unwrap()
                    .join("\n")
                    .contains("https://"));
                assert!(!printer
                    .ordinary
                    .lock()
                    .unwrap()
                    .join("\n")
                    .contains("https://"));
            }
        }
    }

    #[test]
    fn image_downloads_are_bound_to_the_issuer_origin() {
        let origin = "https://tenant.example";
        assert!(image_url("https://tenant.example:443/qr.png?token=fixture", origin).is_ok());
        for source in [
            "http://tenant.example/qr.png",
            "https://other.example/qr.png",
            "https://tenant.example:8443/qr.png",
            "https://user@tenant.example/qr.png",
            "https://tenant.example/qr.png#fragment",
            "https://tenant.example/qr.png\n",
            "//tenant.example/qr.png",
        ] {
            assert!(image_url(source, origin).is_err(), "{source:?}");
        }
        assert!(image_url(
            &format!("https://tenant.example/{}", "x".repeat(2048)),
            origin
        )
        .is_err());
    }

    #[tokio::test]
    async fn rejected_image_preserves_setup_key_and_embedded_images() {
        let mut enrollment = EnrollmentPresentation {
            qr: Some("https://other.example/qr.png".into()),
            setup_key: Some("FIXTUREKEY".into()),
        };
        resolve_image(
            &mut enrollment,
            "https://tenant.example",
            Duration::from_secs(1),
        )
        .await;
        assert!(enrollment.qr.is_none());
        assert_eq!(enrollment.setup_key.as_deref(), Some("FIXTUREKEY"));
        let source = png_source(qr_image());
        enrollment.qr = Some(source.clone());
        resolve_image(&mut enrollment, "https://tenant.example", Duration::ZERO).await;
        assert_eq!(enrollment.qr.as_deref(), Some(source.as_str()));
    }

    // Exercise the real HTTP reader without weakening the production HTTPS/origin check.
    async fn serve_image(
        response: Vec<u8>,
        delay: Duration,
    ) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/qr.png", listener.local_addr().unwrap()))
            .unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(&response).await;
        });
        (url, task)
    }

    #[tokio::test]
    async fn downloaded_png_reaches_greeter_as_enrollment_content() {
        let source = png_source(qr_image());
        let png = STANDARD
            .decode(source.strip_prefix("data:image/png;base64,").unwrap())
            .unwrap();
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", png.len()).into_bytes();
        response.extend_from_slice(&png);
        let (url, server) = serve_image(response, Duration::ZERO).await;
        let downloaded = download_image(&image_client(Duration::from_secs(2)).unwrap(), url)
            .await
            .unwrap();
        server.await.unwrap();
        let printer = Printer::default();
        present(
            &printer,
            "gdm-password",
            &EnrollmentPresentation {
                qr: Some(downloaded),
                setup_key: None,
            },
        )
        .unwrap();
        let messages = printer.sensitive.lock().unwrap();
        let encoded = messages[0].strip_prefix("[OIDC_ENROLL_QR] ").unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap(), PAYLOAD.as_bytes());
    }

    #[tokio::test]
    async fn downloads_reject_errors_and_oversized_bodies() {
        let mut oversized = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        oversized.extend_from_slice(format!("{:x}\r\n", MAX_PNG_BYTES + 1).as_bytes());
        oversized.extend(std::iter::repeat_n(b'x', MAX_PNG_BYTES + 1));
        oversized.extend_from_slice(b"\r\n0\r\n\r\n");
        for response in [
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                MAX_PNG_BYTES + 1
            )
            .into_bytes(),
            oversized,
        ] {
            let (url, server) = serve_image(response, Duration::ZERO).await;
            assert!(
                download_image(&image_client(Duration::from_secs(2)).unwrap(), url)
                    .await
                    .is_err()
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn downloads_do_not_follow_redirects() {
        let (target, target_server) = serve_image(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            Duration::ZERO,
        )
        .await;
        let response =
            format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n")
                .into_bytes();
        let (url, server) = serve_image(response, Duration::ZERO).await;
        assert!(
            download_image(&image_client(Duration::from_secs(2)).unwrap(), url)
                .await
                .is_err()
        );
        assert!(
            !target_server.is_finished(),
            "redirect target must not be requested"
        );
        target_server.abort();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn downloads_time_out_and_reject_invalid_tls() {
        let (url, server) = serve_image(Vec::new(), Duration::from_secs(5)).await;
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            download_image(&image_client(Duration::from_millis(50)).unwrap(), url),
        )
        .await
        .expect("download must honor its request timeout")
        .is_err());
        server.abort();
        let (mut url, server) = serve_image(Vec::new(), Duration::ZERO).await;
        url.set_scheme("https").unwrap();
        assert!(
            download_image(&image_client(Duration::from_secs(2)).unwrap(), url)
                .await
                .is_err()
        );
        server.abort();
    }
}
