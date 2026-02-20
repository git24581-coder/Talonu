import React, { useState, useEffect, useCallback, useRef } from 'react';
import apiClient from '../api/client.js';
import './AdminClasses.css';
import './AdminMobileOptimizations.css';

function AdminClasses() {
  const [classes, setClasses] = useState([]);
  const [teachers, setTeachers] = useState([]);
  const [students, setStudents] = useState([]);
  const [name, setName] = useState('');
  const [teacherId, setTeacherId] = useState('');
  const [message, setMessage] = useState(null);
  const [selectedClass, setSelectedClass] = useState(null);
  const [showClassDetails, setShowClassDetails] = useState(false);
  const [classStudents, setClassStudents] = useState([]);
  const [selectedStudentId, setSelectedStudentId] = useState('');
  const [selectedStudentLabel, setSelectedStudentLabel] = useState('');
  const [studentSearchQuery, setStudentSearchQuery] = useState('');
  const [isStudentPickerOpen, setIsStudentPickerOpen] = useState(false);
  const [newTeacherId, setNewTeacherId] = useState('');
  const studentPickerRef = useRef(null);

  const apiCall = async (method, path, data) => {
    try {
      if (method === 'GET') return (await apiClient.get(path)).data;
      if (method === 'POST') return (await apiClient.post(path, data)).data;
      if (method === 'PUT') return (await apiClient.put(path, data)).data;
      if (method === 'DELETE') return (await apiClient.delete(path)).data;
    } catch (e) {
      throw e;
    }
  };

  const load = useCallback(async () => {
    try {
      const cls = await apiCall('GET', '/api/classes');
      setClasses(cls || []);
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Не вдалося завантажити класи' });
    }
    try {
      const users = await apiClient.get('/api/users');
      const allUsers = users.data || [];
      const sortedStudents = allUsers
        .filter((u) => u.role === 'student')
        .sort((a, b) => (a.name || a.username || '').localeCompare(b.name || b.username || '', 'uk'));
      setTeachers(allUsers.filter((u) => u.role === 'teacher'));
      setStudents(sortedStudents);
    } catch (e) {
      console.error('Error loading users:', e);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!isStudentPickerOpen) return undefined;

    const handleClickOutside = (event) => {
      if (studentPickerRef.current && !studentPickerRef.current.contains(event.target)) {
        setIsStudentPickerOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isStudentPickerOpen]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setMessage(null);
    try {
      const resp = await apiClient.post('/api/classes', { name, teacher_id: teacherId || null });
      setMessage({ type: 'success', text: `Клас "${resp.data.name}" створено!` });
      setName('');
      setTeacherId('');
      load();
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка створення класу' });
    }
  };

  const handleSelectClass = async (cls) => {
    setSelectedClass(cls);
    setNewTeacherId(cls.teacher_id || '');
    setSelectedStudentId('');
    setSelectedStudentLabel('');
    setStudentSearchQuery('');
    setIsStudentPickerOpen(false);
    
    // Load students in this class
    try {
      const users = await apiClient.get('/api/users');
      const clsStudents = (users.data || []).filter((u) => u.class_id === cls.id && u.role === 'student');
      setClassStudents(clsStudents);
    } catch (e) {
      console.error('Error loading class students:', e);
    }
    
    setShowClassDetails(true);
  };

  const handleAssignTeacher = async () => {
    if (!selectedClass) return;
    setMessage(null);
    try {
      await apiClient.put(`/api/classes/${selectedClass.id}/teacher`, { teacher_id: newTeacherId || null });
      setMessage({ type: 'success', text: 'Вчителя призначено!' });
      load();
      setShowClassDetails(false);
      setSelectedClass(null);
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка при призначенні вчителя' });
    }
  };

  const handleAddStudent = async () => {
    if (!selectedClass || !selectedStudentId) {
      setMessage({ type: 'error', text: 'Виберіть учня' });
      return;
    }
    const selectedStudent = students.find((u) => u.id === selectedStudentId && u.role === 'student');
    if (!selectedStudent) {
      setMessage({ type: 'error', text: 'Можна додавати тільки учнів' });
      return;
    }
    if (selectedStudent.class_id && selectedStudent.class_id !== selectedClass.id) {
      setMessage({ type: 'error', text: 'Учень вже закріплений за іншим класом' });
      return;
    }
    setMessage(null);
    try {
      await apiClient.post(`/api/classes/${selectedClass.id}/students`, { student_id: selectedStudentId });
      setMessage({ type: 'success', text: 'Учня додано до класу!' });
      setSelectedStudentId('');
      setSelectedStudentLabel('');
      setStudentSearchQuery('');
      setIsStudentPickerOpen(false);
      
      // Reload class details
      const users = await apiClient.get('/api/users');
      const clsStudents = (users.data || []).filter((u) => u.class_id === selectedClass.id && u.role === 'student');
      setClassStudents(clsStudents);
      
      load();
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка при додаванні учня' });
    }
  };

  const handleRemoveStudent = async (studentId) => {
    if (!selectedClass) return;
    if (!window.confirm('Видалити учня з класу?')) return;
    
    setMessage(null);
    try {
      await apiClient.delete(`/api/classes/${selectedClass.id}/students/${studentId}`);
      setMessage({ type: 'success', text: 'Учня видалено з класу!' });
      
      // Reload class details
      const users = await apiClient.get('/api/users');
      const clsStudents = (users.data || []).filter((u) => u.class_id === selectedClass.id && u.role === 'student');
      setClassStudents(clsStudents);
      
      load();
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка при видаленні учня' });
    }
  };

  const handleDeleteClass = async (classId) => {
    if (!window.confirm('Видалити цей клас? Це не вилучить учнів, тільки видалить клас.')) return;
    
    setMessage(null);
    try {
      await apiClient.delete(`/api/classes/${classId}`);
      setMessage({ type: 'success', text: 'Клас видалено!' });
      setShowClassDetails(false);
      setSelectedClass(null);
      load();
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка при видаленні класу' });
    }
  };

  const getStudentLabel = (student) => {
    const namePart = (student.name || '').trim() || 'Без імені';
    const usernamePart = student.username ? `@${student.username}` : 'без логіну';
    const className = classes.find((c) => c.id === student.class_id)?.name;
    return className
      ? `${namePart} · ${usernamePart} · клас ${className}`
      : `${namePart} · ${usernamePart}`;
  };

  const getAvailableStudents = () => {
    const classStudentIds = new Set(classStudents.map((s) => s.id));
    return students
      .filter((s) => s.role === 'student')
      .filter((s) => !s.class_id)
      .filter((s) => !classStudentIds.has(s.id));
  };

  const availableStudents = getAvailableStudents();
  const normalizedStudentSearch = studentSearchQuery.trim().toLowerCase();
  const filteredAvailableStudents = availableStudents.filter((student) => {
    if (!normalizedStudentSearch) return true;
    const label = getStudentLabel(student).toLowerCase();
    return (
      String(student.name || '').toLowerCase().includes(normalizedStudentSearch) ||
      String(student.username || '').toLowerCase().includes(normalizedStudentSearch) ||
      label.includes(normalizedStudentSearch)
    );
  });

  return (
    <div className="container">
      <h2>📚 Управління класами</h2>
      {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}

      {!showClassDetails ? (
        <>
          <div className="card" style={{ marginBottom: 20 }}>
            <h3>➕ Створити новий клас</h3>
            <form onSubmit={handleCreate} className="class-create-form-row">
              <input 
                className="class-create-input"
                placeholder="Назва класу (наприклад, 5-A)" 
                title="Введіть назву класу"
                value={name} 
                onChange={e=>setName(e.target.value)} 
                required
              />
              <select 
                className="class-create-select"
                value={teacherId} 
                title="Виберіть вчителя для цього класу (факультативно)"
                onChange={e=>setTeacherId(e.target.value)}
              >
                <option value="">(Без вчителя)</option>
                {teachers.map(t=> <option key={t.id} value={t.id}>{t.name || t.username}</option>)}
              </select>
              <button 
                className="btn-primary" 
                type="submit"
                title="Натисніть для створення нового класу"
              >
                Створити
              </button>
            </form>
          </div>

          <div className="card">
            <h3>📋 Список класів ({classes.length})</h3>
            {classes.length === 0 ? (
              <div className="alert alert-info">Класи не знайдені</div>
            ) : (
              <div className="classes-table-wrapper">
                <table className="classes-table">
                  <thead>
                    <tr>
                      <th>Назва</th>
                      <th>Вчитель</th>
                      <th style={{textAlign: 'center'}}>Учнів</th>
                      <th style={{textAlign: 'center'}}>Дії</th>
                    </tr>
                  </thead>
                  <tbody>
                    {classes.map(c => (
                      <tr key={c.id}>
                        <td><strong>{c.name}</strong></td>
                        <td>{c.teacher_name || c.teacher_username || '—'}</td>
                        <td style={{textAlign: 'center'}}>{c.student_count || 0}</td>
                        <td style={{textAlign: 'center'}}>
                          <button 
                            onClick={() => handleSelectClass(c)}
                            className="btn-secondary btn-small"
                            title="Натисніть для редагування цього класу, призначення вчителя та керування учнями"
                          >
                            Редагувати
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="card">
          <h2>📝 Редагування класу: <strong>{selectedClass.name}</strong></h2>
          
          {/* Teacher Assignment */}
          <div style={{marginBottom: '30px', padding: '15px', backgroundColor: '#f8f9fa', borderRadius: '8px'}}>
            <h4>👨‍🏫 Призначення вчителя</h4>
            <div className="class-detail-control-row">
              <select 
                className="class-detail-select"
                value={newTeacherId}
                title="Виберіть вчителя для цього класу"
                onChange={e => setNewTeacherId(e.target.value)}
              >
                <option value="">(Без вчителя)</option>
                {teachers.map(t => (
                  <option key={t.id} value={t.id}>
                    {t.name || t.username} {selectedClass.teacher_id === t.id ? '✓' : ''}
                  </option>
                ))}
              </select>
              <button 
                onClick={handleAssignTeacher}
                className="btn-primary"
                title="Натисніть для призначення вибраного вчителя до класу"
              >
                Призначити
              </button>
            </div>
          </div>

          {/* Students List */}
          <div style={{marginBottom: '30px'}}>
            <h4>👨‍🎓 Учні класу ({classStudents.length})</h4>
            {classStudents.length === 0 ? (
              <div className="alert alert-info">Учнів у класі немає</div>
            ) : (
              <div className="students-table-wrapper">
                <table className="students-table">
                  <thead>
                    <tr>
                      <th>Ім'я</th>
                      <th>Логін</th>
                      <th style={{textAlign: 'center'}}>Дія</th>
                    </tr>
                  </thead>
                  <tbody>
                    {classStudents.map(st => (
                      <tr key={st.id}>
                        <td>{st.name}</td>
                        <td><code>{st.username}</code></td>
                        <td style={{textAlign: 'center'}}>
                          <button 
                            onClick={() => handleRemoveStudent(st.id)}
                            className="btn-remove"
                            title="Натисніть для видалення цього учня з класу"
                          >
                            Видалити
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Add Student */}
          <div style={{marginBottom: '30px', padding: '15px', backgroundColor: '#e8f5e9', borderRadius: '8px'}}>
            <h4 style={{ marginTop: 0, marginBottom: '10px' }}>➕ Додати учня</h4>
            <div className="class-detail-control-row">
              <div className="class-student-picker" ref={studentPickerRef}>
                <input
                  type="text"
                  className="class-detail-select class-student-search-input"
                  value={studentSearchQuery}
                  title="Натисніть та вводьте текст для пошуку учня"
                  placeholder="Пошук учня за ім'ям або логіном"
                  onFocus={() => setIsStudentPickerOpen(true)}
                  onClick={() => setIsStudentPickerOpen(true)}
                  onChange={(e) => {
                    setStudentSearchQuery(e.target.value);
                    setSelectedStudentId('');
                    setSelectedStudentLabel('');
                    setIsStudentPickerOpen(true);
                  }}
                />

                {isStudentPickerOpen && (
                  <div className="class-student-options">
                    {availableStudents.length === 0 ? (
                      <div className="class-student-empty">Немає доступних учнів</div>
                    ) : filteredAvailableStudents.length === 0 ? (
                      <div className="class-student-empty">Нічого не знайдено за вашим запитом</div>
                    ) : (
                      filteredAvailableStudents.map((student) => (
                        <button
                          key={student.id}
                          type="button"
                          className={`class-student-option ${selectedStudentId === student.id ? 'active' : ''}`}
                          onClick={() => {
                            const label = getStudentLabel(student);
                            setSelectedStudentId(student.id);
                            setSelectedStudentLabel(label);
                            setStudentSearchQuery(label);
                            setIsStudentPickerOpen(false);
                          }}
                        >
                          <div className="class-student-option-main">{student.name || 'Без імені'}</div>
                          <div className="class-student-option-sub">@{student.username || 'без логіну'}</div>
                        </button>
                      ))
                    )}
                  </div>
                )}

                {selectedStudentId && (
                  <div className="class-student-selected-hint">
                    Вибрано: {selectedStudentLabel}
                  </div>
                )}
              </div>
              <button 
                onClick={handleAddStudent}
                className="btn-primary"
                title="Натисніть для додавання вибраного учня до класу"
                disabled={!selectedStudentId}
              >
                Додати
              </button>
            </div>
          </div>

          {/* Back and Delete Buttons */}
          <div className="class-detail-actions" style={{paddingTop: '15px', borderTop: '1px solid #ddd'}}>
            <button 
              onClick={() => {
                setShowClassDetails(false);
                setSelectedClass(null);
                setSelectedStudentId('');
                setSelectedStudentLabel('');
                setStudentSearchQuery('');
                setIsStudentPickerOpen(false);
              }}
              className="btn-secondary"
              title="Натисніть для повернення до списку класів"
            >
              ← Назад
            </button>
            <button 
              className="btn-danger"
              onClick={() => handleDeleteClass(selectedClass.id)}
              title="Натисніть для видалення цього класу (учні не будуть видалені)"
            >
              🗑️ Видалити клас
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminClasses;

