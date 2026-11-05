{ lib ? import <nixpkgs/lib> }:
let
  settings = (lib.evalModules {
    modules = [
      ../modules/himmelblau-options.nix
      {
        services.himmelblau.settings = {
          home_prefix = "/home/shared/";
          tenant.work = {
            domain = "work.example";
            default = true;
            domain_aliases = [ "alias.example" "other.example" ];
            idmap_range = "200000-999999";
          };
          tenant.partners = {
            type = "oidc";
            domain = "partners.example";
            oidc_issuer_url = "https://id.partners.example";
            app_id = "linux";
            idmap_range = "1000000-1999999";
            home_prefix = "/home/partners/";
            oidc_account_id_strip_at_suffix = false;
          };
        };
      }
    ];
  }).config.services.himmelblau.settings;
  module = import ../modules/himmelblau.nix {
    inherit lib;
    config.services.himmelblau = {
      enable = true;
      inherit settings;
    };
    pkgs.formats.ini = _: {
      generate = _: value: value;
    };
  };
in
module.config.content.environment.etc."himmelblau/himmelblau.conf".source
