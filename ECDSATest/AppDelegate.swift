//
//  AppDelegate.swift
//  ECDSATest
//
//  Copyright © AwesomeCompany. All rights reserved.
//

import UIKit

class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    lazy private var router = RootRouter()
    lazy private var deeplinkHandler = DeeplinkHandler()
    lazy private var notificationsHandler = NotificationsHandler()

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.makeKeyAndVisible()

        // Notifications
        notificationsHandler.configure()

        // App structure
        router.loadMainAppStructure()

        // Enrolling a keychain item into Face ID cannot happen immediately on launch
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(300)) {
            self.encryptionTest()
        }

        return true
    }

    func encryptionTest() {
        let tag = "tag-enclave4"
        let ecdsa = ECDSAEncryption(useSecureEnclave: true, tag: tag)
        do {
            let encrypted: String
            if let string = UserDefaults.standard.string(forKey: tag) {
                encrypted = string
                print("encrypted: \(encrypted)")
            } else {
                let input = Data("test string".utf8)
                let encryptedNewly = try ecdsa.encrypt(input: input)
                UserDefaults.standard.set(encryptedNewly, forKey: tag)
                print("encryptedNewly: \(encryptedNewly)")
                encrypted = encryptedNewly
            }
            let decrypted = try ecdsa.decrypt(input: encrypted)
            // swiftlint:disable:next force_unwrapping
            print("decrypted: \(String(data: decrypted, encoding: .utf8)!)")
        } catch let error {
            print("error: \(error)")
        }
    }

    func application(_ application: UIApplication,
                     continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        // To enable full universal link functionality add and configure the associated domain capability
        // https://developer.apple.com/library/content/documentation/General/Conceptual/AppSearch/UniversalLinks.html
        if userActivity.activityType == NSUserActivityTypeBrowsingWeb, let url = userActivity.webpageURL {
            deeplinkHandler.handleDeeplink(with: url)
        }
        return true
    }

    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
        // To enable full remote notifications functionality you should first register the device with your api service
        //https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/
        notificationsHandler.handleRemoteNotification(with: userInfo)
    }
}
