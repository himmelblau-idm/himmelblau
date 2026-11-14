/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
#[allow(unused_imports)]
use dbus::arg;
use dbus::blocking::Connection;
use dbus_crossroads as crossroads;

pub trait DeviceBroker {
    fn sign(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn generate_key_pair(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn load_key_pair(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn persist_key(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn generate_derived_key(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn delete_key(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn decrypt(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn generate_pkcs10_cert_signing_request(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn asymmetric_key_exists(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn asymmetric_key_with_thumbprint_exists(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn get_asymmetric_key_thumbprint(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn generate_asymmetric_key(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn get_asymmetric_key_creation_date(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn clear_asymmetric_key(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn get_request_confirmation(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn mint_signed_access_token(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn mint_signed_http_request(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
    fn make_http_request_with_client_tls(
        &mut self,
        session_id: String,
        request_json: String,
    ) -> Result<String, dbus::MethodErr>;
}

pub fn register_device_broker<T>(
    cr: &mut crossroads::Crossroads,
) -> crossroads::IfaceToken<T>
where
    T: DeviceBroker + Send + 'static,
{
    cr.register("com.microsoft.identity.DeviceBroker1", |b| {
        b.method(
            "sign",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.sign(session_id, request_json).map(|x| (x,))
            },
        );
        b.method(
            "generateKeyPair",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.generate_key_pair(session_id, request_json).map(|x| (x,))
            },
        );
        b.method(
            "loadKeyPair",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.load_key_pair(session_id, request_json).map(|x| (x,))
            },
        );
        b.method(
            "persistKey",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.persist_key(session_id, request_json).map(|x| (x,))
            },
        );
        b.method(
            "generateDerivedKey",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.generate_derived_key(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "deleteKey",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.delete_key(session_id, request_json).map(|x| (x,))
            },
        );
        b.method(
            "decrypt",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.decrypt(session_id, request_json).map(|x| (x,))
            },
        );
        b.method(
            "generatePKCS10CertSigningRequest",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.generate_pkcs10_cert_signing_request(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "asymmetricKeyExists",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.asymmetric_key_exists(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "asymmetricKeyWithThumbprintExists",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.asymmetric_key_with_thumbprint_exists(
                    session_id,
                    request_json,
                )
                .map(|x| (x,))
            },
        );
        b.method(
            "getAsymmetricKeyThumbprint",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.get_asymmetric_key_thumbprint(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "generateAsymmetricKey",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.generate_asymmetric_key(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "getAsymmetricKeyCreationDate",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.get_asymmetric_key_creation_date(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "clearAsymmetricKey",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.clear_asymmetric_key(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "getRequestConfirmation",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.get_request_confirmation(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "mintSignedAccessToken",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.mint_signed_access_token(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "mintSignedHttpRequest",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.mint_signed_http_request(session_id, request_json)
                    .map(|x| (x,))
            },
        );
        b.method(
            "makeHttpRequestWithClientTls",
            ("session_id", "request_json"),
            ("result",),
            |_, t: &mut T, (session_id, request_json)| {
                t.make_http_request_with_client_tls(session_id, request_json)
                    .map(|x| (x,))
            },
        );
    })
}

pub async fn device_broker_serve<T>(broker: T) -> Result<(), dbus::MethodErr>
where
    T: DeviceBroker + Send + 'static,
{
    // Start up a connection to the system bus and request a name
    let c = Connection::new_system()?;
    c.request_name("com.microsoft.identity.DeviceBroker1", false, true, false)?;

    let mut cr = crossroads::Crossroads::new();
    let token = register_device_broker::<T>(&mut cr);

    cr.insert("/com/microsoft/identity/devicebroker1", &[token], broker);

    // Serve clients forever.
    cr.serve(&c)?;
    unreachable!()
}
