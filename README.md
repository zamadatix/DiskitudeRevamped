# Diskitude Revamped

Diskitude Revamped is a modernized clone of the fantastic [Diskitude](https://madebyevan.com/diskitude/) Windows app by Evan Wallace. It shares the same base feature set plus many enhancements while being smaller (<= 8 kB instead of <=10 kB).

<img width="1573" height="828" alt="image" src="https://github.com/user-attachments/assets/b1fe1138-f72e-4867-be34-36d9b627f3d5" />

LLMs were used to aid development.

## Use

Run `DiskitudeRevamped.exe` and choose a specific drive or folder to scan. You can also choose to simultaneously scan and display all drives by selecting `This PC`. A directory can also be specified directly via argument on launch. Scanning runs in the background, publishes progress while it works, supports Unicode paths, and skips directory reparse points to avoid loops.

In `This PC` mode, each detected drive has its own chart. The layout will attempt to adapt to fit before eventually offering a scrollbar. Empty drives show zero bytes and drives that cannot be opened are marked `Unavailable`.

Hover over an item to see its path, size, and percentage of the displayed tree. Sizes use base-1024 units from bytes through EB.

| Control | Action |
|---|---|
| Click a folder or drive | Make it the center of the chart |
| Ctrl+click | Open a folder in Explorer or select a file there |
| Right-click / Enter | Expand the hovered folder |
| Right-click the center / Backspace | Return to the previous view |
| Home | Return to the original scan root |
| F5 | Rescan the original scope and return to its root |
| F2 | Open another independent scan window |
| C or Ctrl+C | Copy the hovered path, or the current root path |

Refreshing can also detects added or removed drive letters.

## Improvements over the original

- Native 64-bit implementation
- Scanning uses bulk directory reads and up to eight bounded workers for faster scans, particularly for drives with complex directory trees.
- `This PC` provides a scrollable overview of all detected drive letters.
- Keyboard controls for most actions, including newly added ones.
- Light/dark themes, eight clear on-screen control hints, and a 25% larger chart center and rings improve readability while retaining the original font size and blue palette.
- Exact size totals, percentage labels, and human-friendly TB/PB/EB units
- Native Windows drawing removes the OpenGL dependency. The uncompressed executable is 8,173 bytes or about 20% smaller than the original.

## Source and build

`src` contains the complete NASM source and a single PowerShell build script. Install NASM 3.02 or newer and place `nasm.exe` on `PATH`, then run from the `src` directory:

```powershell
.\build.ps1
```

The script creates `DiskitudeRevamped.exe` in the parent directory and verifies that it is a 64-bit Windows GUI executable no larger than 8,192 bytes. The program targets 64-bit Windows 7 or later and has been tested on Windows 11.

## License

Released under the [MIT License](LICENSE).
