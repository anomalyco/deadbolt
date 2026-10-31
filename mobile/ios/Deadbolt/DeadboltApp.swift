import SwiftUI
import UIKit

@main
struct DeadboltApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        RuneFonts.register()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .tint(Rune.text)
                .background(ActivityTracker { model.noteActivity() })
                .task { await model.start() }
                .onChange(of: scenePhase, initial: true) { _, phase in model.scenePhaseChanged(to: phase) }
        }
    }
}

/// Records every touch in the window as activity for the idle lock, without
/// taking the touch from the views underneath.
struct ActivityTracker: UIViewRepresentable {
    let onTouch: @MainActor () -> Void

    func makeUIView(context: Context) -> TrackerView {
        TrackerView(onTouch: onTouch)
    }

    func updateUIView(_ view: TrackerView, context: Context) {}

    final class TrackerView: UIView {
        private let recognizer: TouchRecognizer

        init(onTouch: @escaping @MainActor () -> Void) {
            recognizer = TouchRecognizer(onTouch: onTouch)
            super.init(frame: .zero)
            isUserInteractionEnabled = false
        }

        required init?(coder: NSCoder) { nil }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            recognizer.view?.removeGestureRecognizer(recognizer)
            window?.addGestureRecognizer(recognizer)
        }
    }

    final class TouchRecognizer: UIGestureRecognizer {
        private let onTouch: @MainActor () -> Void

        init(onTouch: @escaping @MainActor () -> Void) {
            self.onTouch = onTouch
            super.init(target: nil, action: nil)
            cancelsTouchesInView = false
            delaysTouchesBegan = false
            delaysTouchesEnded = false
        }

        override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
            onTouch()
            state = .failed
        }

        override func canPrevent(_ preventedGestureRecognizer: UIGestureRecognizer) -> Bool { false }
        override func canBePrevented(by preventingGestureRecognizer: UIGestureRecognizer) -> Bool { false }
    }
}
