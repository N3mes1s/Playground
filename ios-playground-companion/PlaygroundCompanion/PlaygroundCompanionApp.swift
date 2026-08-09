import SwiftUI

@main
struct PlaygroundCompanionApp: App {
    @StateObject private var settings = AppSettings()

    var body: some Scene {
        WindowGroup {
            ExperimentListView()
                .environmentObject(settings)
        }
    }
}
