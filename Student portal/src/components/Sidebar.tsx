import { Upload, FileText } from "lucide-react";

interface SidebarProps {
  currentPage: "dashboard" | "upload";
  onNavigate: (page: "dashboard" | "upload") => void;
}

export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  return (
    <aside className="fixed left-0 top-16 w-64 h-[calc(100vh-4rem)] bg-white border-r border-gray-200">
      <nav className="p-4">
        <ul className="space-y-2">
          <li>
            <button
              onClick={() => onNavigate("upload")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                currentPage === "upload"
                  ? "bg-blue-50 text-blue-700"
                  : "text-gray-700 hover:bg-gray-50"
              }`}
            >
              <Upload className="w-5 h-5" />
              <span>Upload Documents</span>
            </button>
          </li>
          <li>
            <button
              onClick={() => onNavigate("dashboard")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                currentPage === "dashboard"
                  ? "bg-blue-50 text-blue-700"
                  : "text-gray-700 hover:bg-gray-50"
              }`}
            >
              <FileText className="w-5 h-5" />
              <span>My Documents</span>
            </button>
          </li>
        </ul>
      </nav>
    </aside>
  );
}
