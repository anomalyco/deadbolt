cask "deadbolt" do
  version "@VERSION@"
  sha256 "@SHA256@"

  url "@URL@",
      verified: "anoma.ly/release/deadbolt/"
  name "Deadbolt"
  desc "Decentralized password manager"
  homepage "https://deadbolt.pw/"

  livecheck do
    url "https://anoma.ly/release/deadbolt/desktop/stable.json"
    strategy :json do |json|
      json.dig("release", "version")
    end
  end

  depends_on macos: :monterey

  app "Deadbolt.app"
  # The app's own CLI, the same build as the agent the app starts. It and the
  # formula anomalyco/tap/deadbolt both own bin/deadbolt, so brew installs one.
  binary "#{appdir}/Deadbolt.app/Contents/Helpers/deadbolt"

  uninstall quit: "pw.deadbolt.app"

  zap trash: [
    "~/.config/deadbolt",
    "~/.local/share/deadbolt",
    "~/.local/state/deadbolt",
    "~/Library/Application Support/Arc/User Data/NativeMessagingHosts/pw.deadbolt.browser.json",
    "~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/pw.deadbolt.browser.json",
    "~/Library/Application Support/Chromium/NativeMessagingHosts/pw.deadbolt.browser.json",
    "~/Library/Application Support/Google/Chrome/NativeMessagingHosts/pw.deadbolt.browser.json",
    "~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/pw.deadbolt.browser.json",
    "~/Library/Preferences/pw.deadbolt.app.plist",
    "~/Library/Saved Application State/pw.deadbolt.app.savedState",
  ]
end
