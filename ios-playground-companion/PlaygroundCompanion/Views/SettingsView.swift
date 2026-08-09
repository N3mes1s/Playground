import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    @State private var apiKeyDraft = ""
    @State private var githubTokenDraft = ""
    @State private var savedNotice: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Model", selection: Binding(
                        get: { settings.model },
                        set: { settings.model = $0 }
                    )) {
                        ForEach(ClaudeModel.allCases) { model in
                            VStack(alignment: .leading) {
                                Text(model.displayName)
                                Text(model.blurb)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .tag(model)
                        }
                    }

                    if settings.model.supportsEffort {
                        Picker("Effort", selection: Binding(
                            get: { settings.effort },
                            set: { settings.effort = $0 }
                        )) {
                            ForEach(ClaudeEffort.allCases) { effort in
                                Text(effort.displayName).tag(effort)
                            }
                        }
                        .pickerStyle(.segmented)
                    }
                } header: {
                    Text("Claude")
                } footer: {
                    Text(settings.model.supportsEffort
                         ? "Higher effort means deeper reasoning, more tokens, and more latency."
                         : "Haiku 4.5 doesn't take an effort setting.")
                }

                Section {
                    SecureField(
                        settings.hasAnthropicKey ? "Stored — enter a new key to replace" : "sk-ant-…",
                        text: $apiKeyDraft
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    Button("Save API key") {
                        settings.setAnthropicAPIKey(apiKeyDraft)
                        apiKeyDraft = ""
                        savedNotice = "API key saved to the keychain."
                    }
                    .disabled(apiKeyDraft.trimmingCharacters(in: .whitespaces).isEmpty)

                    if settings.hasAnthropicKey {
                        Button("Remove API key", role: .destructive) {
                            settings.setAnthropicAPIKey("")
                            savedNotice = "API key removed."
                        }
                    }
                } header: {
                    Text("Anthropic API key")
                } footer: {
                    Text("Stored in the device keychain and sent only to api.anthropic.com. "
                         + "A key on a device can ultimately be extracted — a shipping app should "
                         + "proxy these calls through a backend that holds the key instead.")
                }

                Section {
                    SecureField(
                        settings.githubToken == nil ? "Optional" : "Stored — enter a new token to replace",
                        text: $githubTokenDraft
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    Button("Save token") {
                        settings.setGitHubToken(githubTokenDraft)
                        githubTokenDraft = ""
                        savedNotice = "GitHub token saved."
                    }
                    .disabled(githubTokenDraft.trimmingCharacters(in: .whitespaces).isEmpty)

                    if settings.githubToken != nil {
                        Button("Remove token", role: .destructive) {
                            settings.setGitHubToken("")
                            savedNotice = "GitHub token removed."
                        }
                    }
                } header: {
                    Text("GitHub token")
                } footer: {
                    Text("Optional. Without one, GitHub allows 60 unauthenticated requests per "
                         + "hour; a read-only token raises that to 5,000.")
                }

                Section {
                    LabeledContent("Owner") {
                        TextField("owner", text: Binding(
                            get: { settings.owner },
                            set: { settings.owner = $0 }
                        ))
                        .multilineTextAlignment(.trailing)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                    LabeledContent("Repository") {
                        TextField("repo", text: Binding(
                            get: { settings.repo },
                            set: { settings.repo = $0 }
                        ))
                        .multilineTextAlignment(.trailing)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                    LabeledContent("Branch") {
                        TextField("main", text: Binding(
                            get: { settings.branch },
                            set: { settings.branch = $0 }
                        ))
                        .multilineTextAlignment(.trailing)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                } header: {
                    Text("Repository")
                } footer: {
                    Text("Point the app at any public repo. Pull to refresh the list after "
                         + "changing this.")
                }

                if let savedNotice {
                    Section {
                        Label(savedNotice, systemImage: "checkmark.circle")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
