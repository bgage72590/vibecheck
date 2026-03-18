"use client";

import { useState, useRef, useCallback } from "react";

const ALLOWED_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".go", ".rs", ".java", ".php",
  ".vue", ".svelte", ".astro",
  ".env", ".yaml", ".yml", ".toml", ".json",
  ".html", ".htm", ".sql",
]);

function getExtension(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.substring(dot).toLowerCase() : "";
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface UploadZoneProps {
  onFilesSelected: (files: File[], isZip: boolean) => void;
  disabled?: boolean;
}

export function UploadZone({ onFilesSelected, disabled }: UploadZoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isZip, setIsZip] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) setIsDragOver(true);
  }, [disabled]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (disabled) return;

    const droppedFiles = Array.from(e.dataTransfer.files);

    // Check if it's a ZIP
    if (droppedFiles.length === 1 && droppedFiles[0].name.endsWith(".zip")) {
      setSelectedFiles(droppedFiles);
      setIsZip(true);
      return;
    }

    // Filter to source files
    const sourceFiles = droppedFiles.filter(f => ALLOWED_EXTENSIONS.has(getExtension(f.name)));
    if (sourceFiles.length > 0) {
      setSelectedFiles(sourceFiles);
      setIsZip(false);
    }
  }, [disabled]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return;
    const files = Array.from(e.target.files);
    const sourceFiles = files.filter(f => ALLOWED_EXTENSIONS.has(getExtension(f.name)));
    if (sourceFiles.length > 0) {
      setSelectedFiles(sourceFiles);
      setIsZip(false);
    }
  }, []);

  const handleZipInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || !e.target.files[0]) return;
    setSelectedFiles([e.target.files[0]]);
    setIsZip(true);
  }, []);

  const handleScan = useCallback(() => {
    if (selectedFiles.length > 0) {
      onFilesSelected(selectedFiles, isZip);
    }
  }, [selectedFiles, isZip, onFilesSelected]);

  const handleClear = useCallback(() => {
    setSelectedFiles([]);
    setIsZip(false);
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (zipInputRef.current) zipInputRef.current.value = "";
  }, []);

  const totalSize = selectedFiles.reduce((s, f) => s + f.size, 0);

  return (
    <div className="space-y-4">
      {/* Drop zone */}
      <div
        onDragOver={handleDragOver}
        onDragEnter={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${
          disabled
            ? "border-gray-700 opacity-50 cursor-not-allowed"
            : isDragOver
              ? "border-cyan-400 bg-cyan-400/10"
              : "border-gray-600 hover:border-gray-500"
        }`}
        onClick={() => !disabled && fileInputRef.current?.click()}
      >
        <div className="text-4xl mb-4">
          {isDragOver ? "+" : "^"}
        </div>
        <p className="text-lg font-medium mb-2">
          {isDragOver ? "Drop files here" : "Drag & drop your project files"}
        </p>
        <p className="text-gray-500 text-sm mb-4">
          or use the buttons below
        </p>
        <div className="flex gap-3 justify-center" onClick={e => e.stopPropagation()}>
          <button
            type="button"
            disabled={disabled}
            onClick={() => fileInputRef.current?.click()}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            Browse Files
          </button>
          <button
            type="button"
            disabled={disabled}
            onClick={() => zipInputRef.current?.click()}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            Upload ZIP
          </button>
        </div>
        <p className="text-gray-600 text-xs mt-4">
          Supports .js, .ts, .py, .env, .yaml, .json, and more. Max 5MB.
        </p>
      </div>

      {/* Hidden inputs */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleFileInput}
      />
      <input
        ref={zipInputRef}
        type="file"
        accept=".zip"
        className="hidden"
        onChange={handleZipInput}
      />

      {/* File preview */}
      {selectedFiles.length > 0 && (
        <div className="bg-[#1a1a2e] rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-medium">
              {isZip
                ? `ZIP: ${selectedFiles[0].name}`
                : `${selectedFiles.length} file${selectedFiles.length > 1 ? "s" : ""} selected`}
            </h3>
            <span className="text-sm text-gray-500">{formatSize(totalSize)}</span>
          </div>

          {!isZip && (
            <div className="max-h-40 overflow-y-auto mb-3 space-y-1">
              {selectedFiles.map((file, i) => (
                <div key={i} className="flex justify-between text-sm">
                  <span className="text-cyan-400 font-mono truncate">{file.name}</span>
                  <span className="text-gray-600 ml-2 shrink-0">{formatSize(file.size)}</span>
                </div>
              ))}
            </div>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={handleScan}
              disabled={disabled}
              className="px-6 py-2 bg-green-600 hover:bg-green-500 rounded-lg font-medium transition-colors disabled:opacity-50"
            >
              Scan Now
            </button>
            <button
              type="button"
              onClick={handleClear}
              disabled={disabled}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors disabled:opacity-50"
            >
              Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
