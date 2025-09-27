{
  "targets": [
    {
      "target_name": "proctor_native",
      "sources": [
        "src/addon.cc",
        "src/ProcessWatcher.cpp",
        "src/VMDetector.cpp",
        "src/NotificationBlocker.cpp"
      ],
      "conditions": [
        ["OS=='mac'", {
          "sources": [
            "src/PermissionChecker.mm",
            "src/ScreenWatcher_mac.mm",
            "src/ClipboardWatcher_mac.mm",
            "src/FocusIdleWatcher_mac.mm",
            "src/SystemDetector_mac.mm",
            "src/SmartDeviceDetector_mac.mm"
          ]
        }],
        ["OS=='win'", {
          "sources": [
            "src/PermissionChecker_win.cpp",
            "src/ScreenWatcher_win.cpp",
            "src/ClipboardWatcher.cpp",
            "src/FocusIdleWatcher.cpp",
            "src/SystemDetector_win.cpp",
            "src/SmartDeviceDetector_win.cpp"
          ]
        }]
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.7"
      },
      "link_settings": {
        "conditions": [
          ["OS=='mac'", {
            "libraries": [
              "-framework CoreFoundation",
              "-framework DiskArbitration", 
              "-framework IOKit",
              "-framework CoreGraphics",
              "-framework ApplicationServices",
              "-framework Cocoa",
              "-framework Foundation",
              "-framework AVFoundation",
              "-framework AppKit",
              "-framework IOBluetooth"
            ]
          }],
          ["OS=='win'", {
            "libraries": [
              "setupapi.lib",
              "user32.lib",
              "gdi32.lib",
              "iphlpapi.lib",
              "advapi32.lib",
              "ws2_32.lib",
              "oleacc.lib",
              "ole32.lib",
              "psapi.lib",
              "dwmapi.lib",
              "shell32.lib",
              "wbemuuid.lib",
              "oleaut32.lib",
              "strmiids.lib",
              "uuid.lib",
              "Bthprops.lib",
              "dxgi.lib",
              "d3d11.lib"
            ]
          }]
        ]
      },
      "msvs_settings": {
        "VCCLCompilerTool": {
          "ExceptionHandling": 1
        }
      }
    }
  ]
}