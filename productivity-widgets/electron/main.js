const { app, BrowserWindow, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');

let mainWindow;

function todoStorePath() {
  return path.join(app.getPath('userData'), 'todos.json');
}

async function readTodos() {
  const storagePath = todoStorePath();

  try {
    const raw = await fs.readFile(storagePath, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      exists: true,
      storagePath,
      todos: Array.isArray(parsed) ? parsed : []
    };
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.warn('Failed to read todos store:', error);
    }

    return {
      exists: false,
      storagePath,
      todos: []
    };
  }
}

async function writeTodos(todos) {
  const storagePath = todoStorePath();
  const temporaryPath = `${storagePath}.tmp`;
  const normalizedTodos = Array.isArray(todos) ? todos : [];
  const serialized = JSON.stringify(normalizedTodos, null, 2);

  await fs.mkdir(path.dirname(storagePath), { recursive: true });
  await fs.writeFile(temporaryPath, serialized, 'utf8');
  await fs.rename(temporaryPath, storagePath);

  return {
    storagePath,
    count: normalizedTodos.length
  };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 980,
    minHeight: 640,
    transparent: true,
    frame: false,
    resizable: true,
    hasShadow: false,
    backgroundColor: '#00000000',
    title: 'Productivity Widgets',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.handle('window:minimize', () => {
  mainWindow?.minimize();
});

ipcMain.handle('window:close', () => {
  mainWindow?.close();
});

ipcMain.handle('window:toggle-pin', () => {
  if (!mainWindow) {
    return false;
  }

  const nextState = !mainWindow.isAlwaysOnTop();
  mainWindow.setAlwaysOnTop(nextState, 'screen-saver');
  return nextState;
});

ipcMain.handle('todo-store:load', readTodos);
ipcMain.handle('todo-store:save', (_event, todos) => writeTodos(todos));
