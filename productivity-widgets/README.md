# Productivity Widgets

Windows 11 transparent desktop widget built with Electron. It contains:

- Monthly desktop calendar with todo counts on matching dates.
- Four-quadrant todo cards using red, yellow, green, and blue-black acrylic styles.
- Todo entry with a date range and repeat rule: once, workdays, weekends, or daily.
- Local persistence through `localStorage`; no backend is required.

## Run

```powershell
cd E:\working_space\scratch-tools\productivity-widgets
npm install
npm start
```

If Electron binary download is slow, use a mirror:

```powershell
$env:ELECTRON_MIRROR='https://npmmirror.com/mirrors/electron/'
npm install
npm start
```

## Build Windows Installer

Generate a Windows 11 installer with NSIS:

```powershell
cd E:\working_space\scratch-tools\productivity-widgets
npm install
npm run dist
```

If GitHub downloads are slow or blocked in China, use the mirror script:

```powershell
npm run dist:cn
```

The installer is written to:

```text
E:\working_space\scratch-tools\productivity-widgets\release\Productivity Widgets-Setup-0.1.0-x64.exe
```

For a fast unpacked build without an installer:

```powershell
npm run pack
```

## Usage

1. Pick a quadrant card.
2. Click the gear button on a quadrant card.
3. Type the todo title.
4. Choose a start date, optional end date, and repeat rule.
5. Press `Enter` to add it.

The calendar counts unfinished todo occurrences only. Marking an item done removes it from the calendar counts. In the Electron app, todo data is persisted to `todos.json` under Electron's user data directory.
