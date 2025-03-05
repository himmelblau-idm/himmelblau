import St from 'gi://St';
import Clutter from 'gi://Clutter';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as AuthPromptModule from 'resource:///org/gnome/shell/gdm/authPrompt.js';

const GdmAuthPrompt = AuthPromptModule.AuthPrompt;

export default class QrGreeterExtension extends Extension {
    enable() {
        console.log("Himmelblau QR Greeter: enabled...");

        if (!GdmAuthPrompt) {
            console.error("Himmelblau QR Greeter: GdmAuthPrompt is unavailable.");
            return;
        }

        this._originalSetMessage = GdmAuthPrompt.prototype.setMessage;
        const origSetMessage = this._originalSetMessage;

        GdmAuthPrompt.prototype.setMessage = function(message, styleClass) {
            origSetMessage.call(this, message, styleClass);

            if (this._message) {
                this._message.clutter_text.line_wrap = true;
                this._message.set_width(350);
                this._message.set_x_expand(false);
                this._message.set_x_align(Clutter.ActorAlign.CENTER);
            }

            if (!this._qrVBox) {
                const parent = this._message.get_parent();
                parent.remove_child(this._message);

                const vbox = new St.BoxLayout({
                    vertical: true,
                    x_expand: false,
                    y_expand: false,
                    x_align: Clutter.ActorAlign.CENTER,
                    style_class: 'qr-vbox'
                });
                this._qrVBox = vbox;

                vbox.add_child(this._message);

                const qrContainer = new St.Widget({
                    style_class: 'qr-code-container',
                    x_expand: false,
                    y_expand: false,
                    x_align: Clutter.ActorAlign.CENTER
                });
                this._qrContainer = qrContainer;
                vbox.add_child(qrContainer);

                const qrLabel = new St.Label({
                    text: "Scan with your phone",
                    style_class: 'qr-instruction-label'
                });
                this._qrLabel = qrLabel;
                vbox.add_child(qrLabel);

                parent.add_child(vbox);
            }

            const targetUrl = "https://microsoft.com/devicelogin";
            if (message && message.includes(targetUrl)) {
                const fileUri = "file:///usr/share/gnome-shell/extensions/qr-greeter@himmelblau-idm.org/msdag.png";
                this._qrContainer.set_style(`background-image: url('${fileUri}');`);
                this._qrContainer.show();
                this._qrLabel.show();
            } else {
                if (this._qrContainer) this._qrContainer.hide();
                if (this._qrLabel) this._qrLabel.hide();
            }
        };

        console.log("Himmelblau QR Greeter: GdmAuthPrompt.setMessage patched.");
    }

    disable() {
        console.log("Himmelblau QR Greeter: disabled...");
        if (GdmAuthPrompt && this._originalSetMessage) {
            GdmAuthPrompt.prototype.setMessage = this._originalSetMessage;
        }
    }
}
