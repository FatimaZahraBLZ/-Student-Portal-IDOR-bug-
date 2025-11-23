import { useState, useRef } from "react";
import { Upload as UploadIcon, FileText, X } from "lucide-react";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import type { Document } from "../App";
import { API_BASE_URL } from "../config";

interface UploadProps {
  userId: number; // ✅ who is uploading
  authToken: string;
  onUpload: (doc: Document) => void;
  onCancel: () => void;
}

export function Upload({ userId, authToken, onUpload, onCancel }: UploadProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [documentTitle, setDocumentTitle] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);        // ✅
  const [error, setError] = useState<string | null>(null); // ✅
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const file = e.dataTransfer.files[0];
    if (file && file.type === "application/pdf") {
      setSelectedFile(file);
      if (!documentTitle) {
        setDocumentTitle(file.name.replace(".pdf", ""));
      }
    } else {
      alert("Please upload a PDF file only.");
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.type === "application/pdf") {
      setSelectedFile(file);
      if (!documentTitle) {
        setDocumentTitle(file.name.replace(".pdf", ""));
      }
    } else {
      alert("Please upload a PDF file only.");
    }
  };

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert("Please select a file to upload.");
      return;
    }
    if (!documentTitle.trim()) {
      alert("Please enter a document title.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("user_id", String(userId)); // ⚠ vulnerable: backend trusts this

      const res = await fetch(`${API_BASE_URL}/api/documents/upload`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Upload failed");
        setLoading(false);
        return;
      }

      // update parent list
      const fileSizeInMB = (selectedFile.size / (1024 * 1024)).toFixed(1);
      const uploadedDoc: Document = {
        id: data.document.id,
        original_name: data.document.original_name,
        stored_name: data.document.stored_name,
        uploaded_at: data.document.uploaded_at ?? new Date().toISOString(),
        fileSize: `${fileSizeInMB} MB`,
      };
      onUpload(uploadedDoc);

      // reset
      setSelectedFile(null);
      setDocumentTitle("");
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
      setLoading(false);
    } catch (err) {
      setError("Cannot reach server. Is the API running?");
      setLoading(false);
    }
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-gray-900 mb-2">Upload Document</h1>
        <p className="text-gray-600">Upload a new PDF document to your collection</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-gray-900">
            <UploadIcon className="w-5 h-5" />
            Upload PDF File
          </CardTitle>
          <CardDescription>Drag and drop your PDF file or browse to select</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Drag and Drop Area */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
              isDragging
                ? "border-blue-500 bg-blue-50"
                : selectedFile
                ? "border-green-300 bg-green-50"
                : "border-gray-300 bg-gray-50 hover:border-blue-400 hover:bg-blue-50/50"
            }`}
          >
            {selectedFile ? (
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto bg-green-100 rounded-full flex items-center justify-center">
                  <FileText className="w-8 h-8 text-green-600" />
                </div>
                <div>
                  <p className="text-gray-900">{selectedFile.name}</p>
                  <p className="text-gray-500">
                    {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                  </p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleRemoveFile}
                  className="border-red-200 text-red-600 hover:bg-red-50"
                >
                  <X className="w-4 h-4 mr-2" />
                  Remove File
                </Button>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto bg-blue-100 rounded-full flex items-center justify-center">
                  <UploadIcon className="w-8 h-8 text-blue-600" />
                </div>
                <div>
                  <p className="text-gray-700 mb-2">
                    Drag and drop your PDF file here
                  </p>
                  <p className="text-gray-500 mb-4">or</p>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleBrowseClick}
                    className="border-blue-300 text-blue-700 hover:bg-blue-50"
                  >
                    Browse Files
                  </Button>
                </div>
                <p className="text-gray-400">PDF files only, max 10MB</p>
              </div>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf"
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>

          {/* Error */}
          {error && (
            <p className="text-sm text-red-600">
              {error}
            </p>
          )}

          {/* Document Title Field */}
          <div className="space-y-2">
            <Label htmlFor="document-title" className="text-gray-700">
              Document Title
            </Label>
            <Input
              id="document-title"
              type="text"
              placeholder="e.g., Assignment 1 - Introduction to Computer Science"
              value={documentTitle}
              onChange={(e) => setDocumentTitle(e.target.value)}
              className="border-gray-300"
            />
            <p className="text-gray-500">Enter a descriptive title for your document</p>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-4">
            <Button
              onClick={handleUpload}
              disabled={!selectedFile || !documentTitle.trim() || loading}
              className="flex-1 bg-blue-600 hover:bg-blue-700"
            >
              {loading ? (
                "Uploading..."
              ) : (
                <>
                  <UploadIcon className="w-4 h-4 mr-2" />
                  Upload PDF
                </>
              )}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={onCancel}
              className="border-gray-300"
            >
              Cancel
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
