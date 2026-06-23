(async function () {
  const STORAGE_KEY = 'productivity-widgets.todos.v1';
  const WEEKDAYS = ['一', '二', '三', '四', '五', '六', '日'];
  const QUADRANT_LABELS = {
    'urgent-important': '重要且紧急',
    important: '重要不紧急',
    urgent: '紧急不重要',
    neither: '不重要不紧急'
  };
  const REPEAT_LABELS = {
    once: '仅开始日',
    workdays: '工作日',
    weekends: '每周末',
    daily: '每日'
  };
  const tauriInvoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.tauri?.invoke;

  const today = stripTime(new Date());
  let visibleMonth = new Date(today.getFullYear(), today.getMonth(), 1);
  let selectedDate = toDateKey(today);
  let todos = [];

  const monthTitle = document.querySelector('#monthTitle');
  const calendarGrid = document.querySelector('#calendarGrid');
  const weekdayRow = document.querySelector('#weekdayRow');
  const dayAgenda = document.querySelector('#dayAgenda');
  const todayText = document.querySelector('#todayText');

  await init();

  async function init() {
    todos = await loadTodos();

    todayText.textContent = new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long'
    }).format(today);

    weekdayRow.innerHTML = WEEKDAYS.map((day) => `<span>${day}</span>`).join('');

    document.querySelector('#prevMonth').addEventListener('click', () => changeMonth(-1));
    document.querySelector('#nextMonth').addEventListener('click', () => changeMonth(1));
    document.querySelector('#todayButton').addEventListener('click', goToday);
    document.querySelector('#pinWindow').addEventListener('click', togglePin);
    document.querySelector('#minimizeWindow').addEventListener('click', minimizeWindow);
    document.querySelector('#closeWindow').addEventListener('click', closeWindow);

    document.querySelectorAll('.settings-toggle').forEach((button) => {
      button.addEventListener('click', () => toggleSettings(button));
    });

    document.querySelectorAll('.todo-form').forEach((form) => {
      const startInput = form.elements.startDate;
      const titleInput = form.elements.title;
      startInput.value = selectedDate;

      titleInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.isComposing) {
          event.preventDefault();
          addTodo(form);
        }
      });

      form.addEventListener('submit', (event) => {
        event.preventDefault();
        addTodo(form);
      });
    });

    render();
  }

  function render() {
    renderCalendar();
    renderAgenda();
    renderQuadrants();
  }

  function changeMonth(offset) {
    visibleMonth = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() + offset, 1);
    renderCalendar();
  }

  function goToday() {
    visibleMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    selectedDate = toDateKey(today);
    updateFormDates();
    render();
  }

  async function togglePin() {
    const isPinned = await invokeDesktop('window_toggle_pin');
    const button = document.querySelector('#pinWindow');
    button.classList.toggle('active', Boolean(isPinned));
    button.title = isPinned ? '取消置顶' : '置顶窗口';
  }

  async function minimizeWindow() {
    await invokeDesktop('window_minimize');
  }

  async function closeWindow() {
    await invokeDesktop('window_close');
  }

  async function invokeDesktop(command, payload) {
    if (tauriInvoke) {
      return tauriInvoke(command, payload);
    }

    if (window.widgetWindow) {
      const electronCommand = {
        window_minimize: 'minimize',
        window_close: 'close',
        window_toggle_pin: 'togglePin'
      }[command];

      return window.widgetWindow[electronCommand]?.();
    }

    return undefined;
  }

  function toggleSettings(button) {
    const card = button.closest('.quadrant-card');
    const form = card.querySelector('.todo-form');
    const shouldOpen = form.hidden;

    form.hidden = !shouldOpen;
    card.classList.toggle('settings-open', shouldOpen);
    button.classList.toggle('active', shouldOpen);
    button.setAttribute('aria-expanded', String(shouldOpen));
    button.title = shouldOpen ? '收起添加事项设置' : '添加事项设置';

    if (shouldOpen) {
      form.elements.startDate.value = selectedDate;
      requestAnimationFrame(() => form.elements.title.focus());
    }
  }

  function addTodo(form) {
    const formData = new FormData(form);
    const title = String(formData.get('title') || '').trim();
    const startDate = String(formData.get('startDate') || selectedDate);
    const endDate = String(formData.get('endDate') || '');
    const repeat = String(formData.get('repeat') || 'once');
    const quadrant = form.closest('.quadrant-card').dataset.quadrant;

    if (!title) {
      return;
    }

    const normalizedEndDate = endDate && endDate < startDate ? startDate : endDate;
    todos.unshift({
      id: crypto.randomUUID(),
      title,
      quadrant,
      startDate,
      endDate: normalizedEndDate,
      repeat,
      done: false,
      completedDates: [],
      createdAt: new Date().toISOString()
    });

    void saveTodos();
    form.elements.title.value = '';
    form.elements.startDate.value = startDate;
    form.elements.endDate.value = normalizedEndDate;
    render();
  }

  function renderCalendar() {
    const formatter = new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: 'long' });
    monthTitle.textContent = formatter.format(visibleMonth);

    const start = calendarStart(visibleMonth);
    const cells = [];

    for (let index = 0; index < 42; index += 1) {
      const date = addDays(start, index);
      const dateKey = toDateKey(date);
      const matching = activeTodosOn(dateKey);
      const preview = matching.slice(0, 2);
      const isToday = dateKey === toDateKey(today);
      const isSelected = dateKey === selectedDate;
      const isOtherMonth = date.getMonth() !== visibleMonth.getMonth();

      cells.push(`
        <button class="day-cell ${isToday ? 'today' : ''} ${isSelected ? 'selected' : ''} ${isOtherMonth ? 'other-month' : ''}" data-date="${dateKey}" type="button">
          <span class="day-number">
            <span>${String(date.getDate()).padStart(2, '0')}</span>
            ${matching.length ? `<span class="count-pill">${matching.length}</span>` : ''}
          </span>
          ${preview.map((todo) => `<span class="calendar-chip">${escapeHtml(todo.title)}</span>`).join('')}
        </button>
      `);
    }

    calendarGrid.innerHTML = cells.join('');
    calendarGrid.querySelectorAll('.day-cell').forEach((cell) => {
      cell.addEventListener('click', () => {
        selectedDate = cell.dataset.date;
        const [year, month] = selectedDate.split('-').map(Number);
        visibleMonth = new Date(year, month - 1, 1);
        updateFormDates();
        render();
      });
    });
  }

  function renderAgenda() {
    const items = activeTodosOn(selectedDate);
    const dateLabel = formatDateLabel(selectedDate);

    if (!items.length) {
      dayAgenda.innerHTML = `
        <h3>${dateLabel}</h3>
        <p class="empty-state">这一天没有待办事项。</p>
      `;
      return;
    }

    dayAgenda.innerHTML = `
      <h3>${dateLabel} · ${items.length} 项待办</h3>
      <div class="agenda-items">
        ${items.map((todo) => `
          <span class="agenda-chip" title="${escapeHtml(todo.title)}">${escapeHtml(todo.title)} · ${QUADRANT_LABELS[todo.quadrant]}</span>
        `).join('')}
      </div>
    `;
  }

  function renderQuadrants() {
    document.querySelectorAll('.quadrant-card').forEach((card) => {
      const quadrant = card.dataset.quadrant;
      const list = card.querySelector('.todo-list');
      const items = todos.filter((todo) => todo.quadrant === quadrant && occursOn(todo, selectedDate));

      if (!items.length) {
        list.innerHTML = '<li class="empty-state">暂无事项</li>';
        return;
      }

      list.innerHTML = items.map((todo) => {
        const range = todo.endDate ? `${todo.startDate} 至 ${todo.endDate}` : todo.startDate;
        const completed = isCompletedOn(todo, selectedDate);
        return `
          <li class="todo-item ${completed ? 'done' : ''}" data-id="${todo.id}">
            <input class="todo-check" type="checkbox" ${completed ? 'checked' : ''} aria-label="完成事项">
            <div class="todo-text">
              <div class="todo-title" title="${escapeHtml(todo.title)}">${escapeHtml(todo.title)}</div>
              <div class="todo-meta">${range} · ${REPEAT_LABELS[todo.repeat] || todo.repeat}</div>
            </div>
            <button type="button" class="delete-todo" title="删除" aria-label="删除">×</button>
          </li>
        `;
      }).join('');

      list.querySelectorAll('.todo-check').forEach((checkbox) => {
        checkbox.addEventListener('change', () => {
          const id = checkbox.closest('.todo-item').dataset.id;
          updateTodoCompletion(id, selectedDate, checkbox.checked);
        });
      });

      list.querySelectorAll('.delete-todo').forEach((button) => {
        button.addEventListener('click', () => {
          const id = button.closest('.todo-item').dataset.id;
          todos = todos.filter((todo) => todo.id !== id);
          void saveTodos();
          render();
        });
      });
    });
  }

  function updateTodoCompletion(id, dateKey, completed) {
    todos = todos.map((todo) => {
      if (todo.id !== id) {
        return todo;
      }

      if (!isRecurringTodo(todo)) {
        return {
          ...todo,
          done: completed,
          completedDates: updateCompletedDates(todo.completedDates, dateKey, completed)
        };
      }

      return {
        ...todo,
        done: false,
        completedDates: updateCompletedDates(todo.completedDates, dateKey, completed)
      };
    });

    void saveTodos();
    render();
  }

  function activeTodosOn(dateKey) {
    return todos.filter((todo) => occursOn(todo, dateKey) && !isCompletedOn(todo, dateKey));
  }

  function isCompletedOn(todo, dateKey) {
    if (!occursOn(todo, dateKey)) {
      return false;
    }

    const completedDates = Array.isArray(todo.completedDates) ? todo.completedDates : [];
    if (completedDates.includes(dateKey)) {
      return true;
    }

    return !isRecurringTodo(todo) && Boolean(todo.done);
  }

  function isRecurringTodo(todo) {
    return todo.repeat === 'daily' || todo.repeat === 'workdays' || todo.repeat === 'weekends';
  }

  function updateCompletedDates(completedDates, dateKey, completed) {
    const dates = new Set(Array.isArray(completedDates) ? completedDates : []);

    if (completed) {
      dates.add(dateKey);
    } else {
      dates.delete(dateKey);
    }

    return Array.from(dates).sort();
  }

  function occursOn(todo, dateKey) {
    if (dateKey < todo.startDate) {
      return false;
    }

    const endDate = todo.endDate || todo.startDate;
    if (dateKey > endDate) {
      return false;
    }

    const date = parseDateKey(dateKey);
    const day = date.getDay();

    switch (todo.repeat) {
      case 'daily':
        return true;
      case 'workdays':
        return day >= 1 && day <= 5;
      case 'weekends':
        return day === 0 || day === 6;
      case 'once':
      default:
        return dateKey === todo.startDate;
    }
  }

  function calendarStart(monthDate) {
    const first = new Date(monthDate.getFullYear(), monthDate.getMonth(), 1);
    const mondayBasedDay = (first.getDay() + 6) % 7;
    return addDays(first, -mondayBasedDay);
  }

  function updateFormDates() {
    document.querySelectorAll('.todo-form').forEach((form) => {
      form.elements.startDate.value = selectedDate;
    });
  }

  async function loadTodos() {
    if (tauriInvoke) {
      try {
        const result = await invokeDesktop('load_todos');
        if (result.exists) {
          const normalized = normalizeTodos(result.todos);
          await persistIfChanged(result.todos, normalized);
          return normalized;
        }
      } catch (error) {
        console.error('Failed to load Tauri todo store:', error);
      }
    }

    if (window.todoStore) {
      try {
        const result = await window.todoStore.load();
        if (result.exists) {
          const normalized = normalizeTodos(result.todos);
          await persistIfChanged(result.todos, normalized);
          return normalized;
        }
      } catch (error) {
        console.error('Failed to load todo store:', error);
      }
    }

    const localTodos = loadLocalTodos();
    if (localTodos) {
      const normalized = normalizeTodos(localTodos);
      await persistIfChanged(localTodos, normalized);

      return normalized;
    }

    const seeded = seedTodos();
    await saveTodosToStores(seeded);
    return seeded;
  }

  function loadLocalTodos() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }

    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  function seedTodos() {
    const start = toDateKey(today);
    const nextWeek = toDateKey(addDays(today, 6));
    const samples = [
      ['处理客户工单', 'urgent-important', 'once', start, ''],
      ['定期检视和优化业务流程', 'important', 'workdays', start, nextWeek],
      ['给朋友安排社交活动', 'urgent', 'weekends', start, nextWeek],
      ['阅读与工作无关的文章', 'neither', 'daily', start, nextWeek]
    ];

    return samples.map(([title, quadrant, repeat, startDate, endDate]) => ({
      id: crypto.randomUUID(),
      title,
      quadrant,
      startDate,
      endDate,
      repeat,
      done: false,
      completedDates: [],
      createdAt: new Date().toISOString()
    }));
  }

  function normalizeTodos(todoList) {
    return todoList.map((todo) => {
      const normalized = {
        ...todo,
        completedDates: Array.isArray(todo.completedDates) ? todo.completedDates : []
      };

      if (isRecurringTodo(normalized) && normalized.done) {
        const completedDates = new Set(normalized.completedDates);

        if (occursOn(normalized, selectedDate)) {
          completedDates.add(selectedDate);
        }

        normalized.done = false;
        normalized.completedDates = Array.from(completedDates).sort();
      }

      return normalized;
    });
  }

  async function persistIfChanged(previousTodos, nextTodos) {
    if (JSON.stringify(previousTodos) !== JSON.stringify(nextTodos)) {
      await saveTodosToStores(nextTodos);
    } else if (window.todoStore) {
      await saveElectronTodos(nextTodos);
    }
  }

  async function saveTodos() {
    await saveTodosToStores(todos);
  }

  async function saveTodosToStores(nextTodos) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(nextTodos));

    await saveElectronTodos(nextTodos);
  }

  async function saveElectronTodos(nextTodos) {
    if (tauriInvoke) {
      try {
        await invokeDesktop('save_todos', { payload: { todos: nextTodos } });
      } catch (error) {
        console.error('Failed to save Tauri todo store:', error);
      }
      return;
    }

    if (window.todoStore) {
      try {
        await window.todoStore.save(nextTodos);
      } catch (error) {
        console.error('Failed to save todo store:', error);
      }
    }
  }

  function parseDateKey(dateKey) {
    const [year, month, day] = dateKey.split('-').map(Number);
    return new Date(year, month - 1, day);
  }

  function toDateKey(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  function stripTime(date) {
    return new Date(date.getFullYear(), date.getMonth(), date.getDate());
  }

  function addDays(date, amount) {
    const next = new Date(date);
    next.setDate(next.getDate() + amount);
    return next;
  }

  function formatDateLabel(dateKey) {
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long'
    }).format(parseDateKey(dateKey));
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    })[char]);
  }
}());
