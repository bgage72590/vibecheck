// A deliberately vulnerable React component for testing vibecheck
import { useState, useEffect } from "react";

export function AdminDashboard() {
  const [user, setUser] = useState(null);
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetch("/api/users").then((r) => r.json()).then(setUsers);
  }, []);

  // VC010: Client-side only admin check
  {user?.role === "admin" && (
    <div>
      <h2>Admin Panel</h2>
      <button onClick={() => fetch("/api/admin/delete-all", { method: "POST" })}>
        Delete All Users
      </button>
    </div>
  )}

  // VC007: XSS via dangerouslySetInnerHTML
  return (
    <div>
      <h1>Dashboard</h1>
      {users.map((u) => (
        <div
          key={u.id}
          dangerouslySetInnerHTML={{ __html: u.bio }}
        />
      ))}
    </div>
  );
}
