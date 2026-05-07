import React, { useCallback, useState } from 'react';
import { Upload, File, X } from 'lucide-react';

export const FileUpload = ({ 
  onFileSelect, 
  accept = "*", 
  multiple = false, 
  label = "Drag & drop files here",
  sublabel = "or click to browse"
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [files, setFiles] = useState([]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(false);
    const droppedFiles = Array.from(e.dataTransfer.files);
    handleFiles(droppedFiles);
  }, []);

  const handleFiles = (newFiles) => {
    const updated = multiple ? [...files, ...newFiles] : newFiles;
    setFiles(updated);
    onFileSelect(multiple ? updated : updated[0]);
  };

  const removeFile = (index) => {
    const updated = files.filter((_, i) => i !== index);
    setFiles(updated);
    onFileSelect(multiple ? updated : null);
  };

  return (
    <div className="space-y-3">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer
          ${isDragOver 
            ? 'border-terracotta bg-terracotta/5 scale-[1.02]' 
            : 'border-sandstone hover:border-terracotta/50 bg-parchment/30 dark:bg-white/5'
          }
        `}
      >
        <input
          type="file"
          accept={accept}
          multiple={multiple}
          onChange={(e) => handleFiles(Array.from(e.target.files))}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />
        <Upload className={`mx-auto mb-3 transition-colors ${isDragOver ? 'text-terracotta' : 'text-warm-gray'}`} size={32} />
        <p className="font-medium text-deep-ink dark:text-ivory">{label}</p>
        <p className="text-sm text-warm-gray mt-1">{sublabel}</p>
      </div>

      {files.length > 0 && (
        <div className="space-y-2">
          {files.map((file, idx) => (
            <div key={idx} className="flex items-center gap-3 p-3 bg-white dark:bg-white/10 rounded-lg border border-sandstone/50">
              <File size={18} className="text-terracotta" />
              <span className="flex-1 text-sm truncate">{file.name}</span>
              <span className="text-xs text-warm-gray">{(file.size / 1024).toFixed(1)} KB</span>
              <button onClick={() => removeFile(idx)} className="hover:text-terracotta transition-colors">
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};