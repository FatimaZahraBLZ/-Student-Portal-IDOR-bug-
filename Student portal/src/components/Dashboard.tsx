import { UploadCloud, Download, Calendar, FileText } from "lucide-react";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import type { Document } from "../App";
import { API_BASE_URL } from "../config";

interface DashboardProps {
  documents: Document[];
  authToken: string;
  userEmail: string;
  onNavigateToUpload: () => void;
}

export function Dashboard({ documents, authToken, userEmail, onNavigateToUpload }: DashboardProps) {
  const handleDownload = async (doc: Document) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/documents/download?file_id=${doc.id}`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        const message = (errorData && errorData.error) || "Download failed";
        alert(message);
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = doc.original_name || `document-${doc.id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert("Cannot download file right now.");
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-gray-900 mb-1">Document Dashboard</h1>
          <p className="text-gray-600">Manage and access your academic documents</p>
        </div>
        <div className="rounded-2xl border border-blue-200 bg-blue-50 text-blue-900 px-4 py-3 shadow-sm flex flex-col sm:flex-row sm:items-center sm:gap-2">
          <span className="text-xs uppercase tracking-[0.2em] text-blue-500">Logged in as</span>
          <span className="text-base font-semibold">{userEmail}</span>
        </div>
      </div>

      {/* Upload Card */}
      <Card className="border-2 border-dashed border-blue-200 bg-blue-50/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-blue-900">
            <UploadCloud className="w-5 h-5" />
            Quick Upload
          </CardTitle>
          <CardDescription>Upload a new PDF document to your collection</CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            onClick={onNavigateToUpload}
            size="lg"
            className="bg-blue-600 hover:bg-blue-700"
          >
            <UploadCloud className="w-5 h-5 mr-2" />
            Upload New PDF
          </Button>
        </CardContent>
      </Card>

      {/* Documents Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-gray-900">
            <FileText className="w-5 h-5" />
            My Documents
          </CardTitle>
          <CardDescription>
            {documents.length} document{documents.length !== 1 ? 's' : ''} uploaded
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border border-gray-200">
            <Table>
              <TableHeader>
                <TableRow className="bg-gray-50">
                  <TableHead>File Name</TableHead>
                  <TableHead>Upload Date</TableHead>
                  <TableHead>File Size</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {documents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center py-8 text-gray-500">
                      No documents uploaded yet. Click "Upload New PDF" to get started.
                    </TableCell>
                  </TableRow>
                ) : (
                  documents.map((doc) => (
                    <TableRow key={doc.id} className="hover:bg-gray-50">
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-blue-600" />
                          <div>
                            <div className="text-gray-900">{doc.original_name}</div>
                            <div className="text-gray-500">{doc.stored_name}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2 text-gray-600">
                          <Calendar className="w-4 h-4" />
                          {new Date(doc.uploaded_at).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          })}
                        </div>
                      </TableCell>
                      <TableCell className="text-gray-600">{doc.fileSize ?? "-"}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          onClick={() => handleDownload(doc)}
                          variant="outline"
                          size="sm"
                          className="border-blue-200 text-blue-700 hover:bg-blue-50"
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Download
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
