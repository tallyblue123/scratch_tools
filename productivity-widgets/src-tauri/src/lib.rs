use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{Manager, Window};

struct PinState(Mutex<bool>);

#[derive(Serialize)]
struct TodoLoadResult {
  exists: bool,
  storage_path: String,
  todos: Vec<Value>,
}

#[derive(Deserialize)]
struct TodoPayload {
  todos: Vec<Value>,
}

fn todo_store_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
  let directory = app.path().app_data_dir().map_err(|error| error.to_string())?;
  Ok(directory.join("todos.json"))
}

#[tauri::command]
fn load_todos(app: tauri::AppHandle) -> Result<TodoLoadResult, String> {
  let storage_path = todo_store_path(&app)?;

  match fs::read_to_string(&storage_path) {
    Ok(raw) => {
      let todos = serde_json::from_str::<Vec<Value>>(&raw).unwrap_or_default();
      Ok(TodoLoadResult {
        exists: true,
        storage_path: storage_path.to_string_lossy().to_string(),
        todos,
      })
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(TodoLoadResult {
      exists: false,
      storage_path: storage_path.to_string_lossy().to_string(),
      todos: Vec::new(),
    }),
    Err(error) => Err(error.to_string()),
  }
}

#[tauri::command]
fn save_todos(app: tauri::AppHandle, payload: TodoPayload) -> Result<(), String> {
  let storage_path = todo_store_path(&app)?;
  let temporary_path = storage_path.with_extension("json.tmp");
  let directory = storage_path
    .parent()
    .ok_or_else(|| String::from("Cannot resolve todo storage directory"))?;

  fs::create_dir_all(directory).map_err(|error| error.to_string())?;

  let serialized = serde_json::to_string_pretty(&payload.todos).map_err(|error| error.to_string())?;
  fs::write(&temporary_path, serialized).map_err(|error| error.to_string())?;
  fs::rename(&temporary_path, &storage_path).map_err(|error| error.to_string())?;

  Ok(())
}

#[tauri::command]
fn window_minimize(window: Window) -> Result<(), String> {
  window.minimize().map_err(|error| error.to_string())
}

#[tauri::command]
fn window_close(window: Window) -> Result<(), String> {
  window.close().map_err(|error| error.to_string())
}

#[tauri::command]
fn window_toggle_pin(window: Window, state: tauri::State<'_, PinState>) -> Result<bool, String> {
  let mut pinned = state.0.lock().map_err(|error| error.to_string())?;
  let next_state = !*pinned;
  window
    .set_always_on_top(next_state)
    .map_err(|error| error.to_string())?;
  *pinned = next_state;
  Ok(next_state)
}

pub fn run() {
  tauri::Builder::default()
    .manage(PinState(Mutex::new(false)))
    .invoke_handler(tauri::generate_handler![
      load_todos,
      save_todos,
      window_minimize,
      window_close,
      window_toggle_pin
    ])
    .run(tauri::generate_context!())
    .expect("error while running Productivity Widgets");
}
