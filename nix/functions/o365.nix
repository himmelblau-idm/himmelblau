{
  lib,
  makeDesktopItem,
  teams-for-linux,
  writeShellScript,
}:

{
  url,
  categories,
  name,
}:
let
  lowerName = lib.toLower name;

  launcher = writeShellScript "launch-${lowerName}" ''
    exec ${teams-for-linux}/bin/teams-for-linux \
      --ssoInTuneEnabled=true \
      --url="${url}" \
      --profile="${name}" \
      --user-data-dir="$HOME/.config/o365-profiles/${lowerName}" \
      --appTitle="${name}" \
      # --appIcon="{config.services.himmelblau.package}/share/icons/hicolor/256x256/apps/o365-{lowerName}.png" \
      # --urlHandler=TODO \
      "$@"
  '';
in
makeDesktopItem {
  name = lowerName;
  desktopName = name;
  icon = "o365-${lowerName}";
  comment = "Open Microsoft 365 ${name}";
  categories = categories;
  exec = "${launcher} %U";
  type = "Application";
  startupNotify = true;
  terminal = false;
}
