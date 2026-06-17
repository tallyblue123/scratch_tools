const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('widgetWindow', {
  minimize: () => ipcRenderer.invoke('window:minimize'),
  close: () => ipcRenderer.invoke('window:close'),
  togglePin: () => ipcRenderer.invoke('window:toggle-pin')
});

contextBridge.exposeInMainWorld('todoStore', {
  load: () => ipcRenderer.invoke('todo-store:load'),
  save: (todos) => ipcRenderer.invoke('todo-store:save', todos)
});
