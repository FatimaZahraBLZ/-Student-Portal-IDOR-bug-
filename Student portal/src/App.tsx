import { useCallback, useEffect, useState } from "react";
import { Navbar } from "./components/Navbar";
import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./components/Dashboard";
import { Upload } from "./components/Upload";
import { Login } from "./components/Login";
import { API_BASE_URL } from "./config";

export interface Document {
  id: number;
  original_name: string;
  stored_name: string;
  uploaded_at: string;
  fileSize?: string;
}

const SESSION_STORAGE_KEY = "student-portal-session";

export default function App() {
  const [user, setUser] = useState<{ id: number; email: string } | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<"dashboard" | "upload">("dashboard");
  const [documents, setDocuments] = useState<Document[]>([]);
  const [documentsLoading, setDocumentsLoading] = useState(false);
  const [documentsError, setDocumentsError] = useState<string | null>(null);

  const fetchDocuments = useCallback(async (userId: number, token: string) => {
    setDocumentsLoading(true);
    setDocumentsError(null);
    try {

      // Vulnerability : The frontend blindly sends user_id and the backend trusts it
      
      const res = await fetch(`${API_BASE_URL}/api/documents?user_id=${userId}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to load documents");
      }

      const normalizedDocs: Document[] = data.map((doc: any) => ({
        id: doc.id,
        original_name: doc.original_name,
        stored_name: doc.stored_name,
        uploaded_at: doc.uploaded_at,
        fileSize: doc.fileSize ?? "-",
      }));

      setDocuments(normalizedDocs);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load documents";
      setDocumentsError(message);
    } finally {
      setDocumentsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user && authToken) {
      fetchDocuments(user.id, authToken);
    } else {
      setDocuments([]);
    }
  }, [user, authToken, fetchDocuments]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const stored = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!stored) return;
    try {
      const parsed = JSON.parse(stored);
      if (parsed?.user && parsed?.token) {
        setUser(parsed.user);
        setAuthToken(parsed.token);
      }
    } catch (err) {
      console.warn("Failed to parse stored session", err);
      localStorage.removeItem(SESSION_STORAGE_KEY);
    }
  }, []);

  const handleUpload = (doc: Document) => {
    setDocuments((prev) => [doc, ...prev]);
    setCurrentPage("dashboard");
  };

  const handleLogin = (session?: { user: { id: number; email: string }; token: string }) => {
    if (!session) return;
    setUser(session.user);
    setAuthToken(session.token);
    if (typeof window !== "undefined") {
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
    }
  };

  const handleLogout = () => {
    setUser(null);
    setAuthToken(null);
    setDocuments([]);
    setCurrentPage("dashboard");
    if (typeof window !== "undefined") {
      localStorage.removeItem(SESSION_STORAGE_KEY);
    }
  };

  if (!user || !authToken) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar onLogout={handleLogout} />
      <div className="flex">
        <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />
        <main className="flex-1 ml-64 mt-16 p-8 space-y-4">
          {documentsError && (
            <div className="text-sm text-red-600 bg-red-50 border border-red-100 rounded-md p-3">
              {documentsError}
            </div>
          )}
          {documentsLoading && (
            <div className="text-sm text-gray-600 bg-gray-50 border border-gray-200 rounded-md p-3">
              Loading documents...
            </div>
          )}
          {currentPage === "dashboard" ? (
            <Dashboard
              documents={documents}
              authToken={authToken}
              userEmail={user.email}
              onNavigateToUpload={() => setCurrentPage("upload")}
            />
          ) : (
            <Upload
              userId={user.id}
              authToken={authToken}
              onUpload={(doc) => {
                handleUpload(doc);
                fetchDocuments(user.id, authToken);
              }}
              onCancel={() => setCurrentPage("dashboard")}
            />
          )}
        </main>
      </div>
    </div>
  );
}
