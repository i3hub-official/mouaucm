// lib/utils/fileUtils.ts

export interface FileValidationResult {
  isValid: boolean;
  error?: string;
}

export class FileUtils {
  // Common file types organized by category
  static readonly FILE_TYPES = {
    // Documents
    DOCUMENTS: ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.md'],
    
    // Images
    IMAGES: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'],
    
    // Spreadsheets
    SPREADSHEETS: ['.xls', '.xlsx', '.csv'],
    
    // Presentations
    PRESENTATIONS: ['.ppt', '.pptx'],
    
    // Archives
    ARCHIVES: ['.zip', '.rar', '.7z'],
    
    // Code files
    CODE: ['.js', '.ts', '.html', '.css', '.json', '.xml', '.yml', '.py', '.java', '.cpp'],
    
    // Audio/Video
    MEDIA: ['.mp3', '.wav', '.mp4', '.avi', '.mov'],
  };

  // Combined list of all allowed file types
  static readonly ALL_ALLOWED_TYPES = [
    ...this.FILE_TYPES.DOCUMENTS,
    ...this.FILE_TYPES.IMAGES,
    ...this.FILE_TYPES.SPREADSHEETS,
    ...this.FILE_TYPES.PRESENTATIONS,
    ...this.FILE_TYPES.ARCHIVES,
    ...this.FILE_TYPES.CODE,
    ...this.FILE_TYPES.MEDIA,
  ];

  // Default size limits
  static readonly SIZE_LIMITS = {
    DOCUMENT: 10 * 1024 * 1024, // 10MB
    IMAGE: 5 * 1024 * 1024,      // 5MB
    SPREADSHEET: 5 * 1024 * 1024, // 5MB
    PRESENTATION: 20 * 1024 * 1024, // 20MB
    ARCHIVE: 50 * 1024 * 1024,    // 50MB
    CODE: 2 * 1024 * 1024,        // 2MB
    MEDIA: 50 * 1024 * 1024,      // 50MB
    DEFAULT: 10 * 1024 * 1024,    // 10MB
  };

  /**
   * Format file size in human-readable format
   */
  static formatFileSize(bytes: number): string {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  /**
   * Get file extension with dot
   */
  static getFileExtension(filename: string): string {
    const ext = filename.split('.').pop()?.toLowerCase();
    return ext ? `.${ext}` : '';
  }

  /**
   * Get file category based on extension
   */
  static getFileCategory(filename: string): string {
    const ext = this.getFileExtension(filename);
    
    for (const [category, extensions] of Object.entries(this.FILE_TYPES)) {
      if (extensions.includes(ext)) {
        return category.toLowerCase();
      }
    }
    
    return 'other';
  }

  /**
   * Get maximum allowed size for a file based on its category
   */
  static getMaxSizeForFile(filename: string): number {
    const category = this.getFileCategory(filename);
    
    switch (category) {
      case 'documents':
        return this.SIZE_LIMITS.DOCUMENT;
      case 'images':
        return this.SIZE_LIMITS.IMAGE;
      case 'spreadsheets':
        return this.SIZE_LIMITS.SPREADSHEET;
      case 'presentations':
        return this.SIZE_LIMITS.PRESENTATION;
      case 'archives':
        return this.SIZE_LIMITS.ARCHIVE;
      case 'code':
        return this.SIZE_LIMITS.CODE;
      case 'media':
        return this.SIZE_LIMITS.MEDIA;
      default:
        return this.SIZE_LIMITS.DEFAULT;
    }
  }

  /**
   * Validate file (checks both type and size)
   */
  static validateFile(file: File, allowedTypes?: string[]): FileValidationResult {
    const extension = this.getFileExtension(file.name);
    
    // Check file type if allowedTypes provided
    if (allowedTypes && allowedTypes.length > 0) {
      if (!allowedTypes.includes(extension)) {
        return {
          isValid: false,
          error: `File type "${extension}" is not allowed. Allowed types: ${allowedTypes.join(', ')}`
        };
      }
    } else {
      // Otherwise check against common types
      if (!this.ALL_ALLOWED_TYPES.includes(extension)) {
        return {
          isValid: false,
          error: `File type "${extension}" is not supported`
        };
      }
    }

    // Check file size based on category
    const maxSize = this.getMaxSizeForFile(file.name);
    if (file.size > maxSize) {
      return {
        isValid: false,
        error: `File size (${this.formatFileSize(file.size)}) exceeds maximum allowed (${this.formatFileSize(maxSize)})`
      };
    }

    return { isValid: true };
  }

  /**
   * Simple validation (just checks if file type is allowed)
   */
  static isAllowedType(filename: string, allowedTypes?: string[]): boolean {
    const extension = this.getFileExtension(filename);
    
    if (allowedTypes && allowedTypes.length > 0) {
      return allowedTypes.includes(extension);
    }
    
    return this.ALL_ALLOWED_TYPES.includes(extension);
  }

  /**
   * Check if file size is within limit
   */
  static isWithinSizeLimit(file: File, customLimit?: number): boolean {
    const limit = customLimit || this.getMaxSizeForFile(file.name);
    return file.size <= limit;
  }

  /**
   * Get file icon based on extension
   */
  static getFileIcon(filename: string): string {
    const ext = this.getFileExtension(filename);
    
    const icons: Record<string, string> = {
      // Documents
      '.pdf': '📄',
      '.doc': '📝',
      '.docx': '📝',
      '.txt': '📄',
      '.rtf': '📄',
      '.md': '📝',
      
      // Images
      '.jpg': '🖼️',
      '.jpeg': '🖼️',
      '.png': '🖼️',
      '.gif': '🎨',
      '.webp': '🖼️',
      '.svg': '🎨',
      
      // Spreadsheets
      '.xls': '📊',
      '.xlsx': '📊',
      '.csv': '📊',
      
      // Presentations
      '.ppt': '📽️',
      '.pptx': '📽️',
      
      // Archives
      '.zip': '📦',
      '.rar': '📦',
      '.7z': '📦',
      
      // Code
      '.js': '💻',
      '.ts': '💻',
      '.html': '🌐',
      '.css': '🎨',
      '.json': '📋',
      '.xml': '📋',
      '.yml': '📋',
      '.py': '🐍',
      '.java': '☕',
      '.cpp': '⚙️',
      
      // Media
      '.mp3': '🎵',
      '.wav': '🎵',
      '.mp4': '🎬',
      '.avi': '🎬',
      '.mov': '🎬',
    };

    return icons[ext] || '📎';
  }

  /**
   * Get human-readable file type description
   */
  static getFileDescription(filename: string): string {
    const ext = this.getFileExtension(filename);
    
    const descriptions: Record<string, string> = {
      '.pdf': 'PDF Document',
      '.doc': 'Word Document',
      '.docx': 'Word Document',
      '.txt': 'Text File',
      '.rtf': 'Rich Text Format',
      '.md': 'Markdown File',
      '.jpg': 'JPEG Image',
      '.jpeg': 'JPEG Image',
      '.png': 'PNG Image',
      '.gif': 'GIF Image',
      '.webp': 'WebP Image',
      '.svg': 'SVG Image',
      '.xls': 'Excel Spreadsheet',
      '.xlsx': 'Excel Spreadsheet',
      '.csv': 'CSV File',
      '.ppt': 'PowerPoint',
      '.pptx': 'PowerPoint',
      '.zip': 'ZIP Archive',
      '.rar': 'RAR Archive',
      '.7z': '7-Zip Archive',
      '.js': 'JavaScript File',
      '.ts': 'TypeScript File',
      '.html': 'HTML File',
      '.css': 'CSS File',
      '.json': 'JSON File',
      '.xml': 'XML File',
      '.yml': 'YAML File',
      '.py': 'Python File',
      '.java': 'Java File',
      '.cpp': 'C++ File',
      '.mp3': 'MP3 Audio',
      '.wav': 'WAV Audio',
      '.mp4': 'MP4 Video',
      '.avi': 'AVI Video',
      '.mov': 'MOV Video',
    };

    return descriptions[ext] || 'Unknown File';
  }

  /**
   * Generate a unique filename for storage
   */
  static generateUniqueFilename(originalName: string): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    const extension = this.getFileExtension(originalName);
    const nameWithoutExt = originalName.replace(extension, '').replace(/[^a-zA-Z0-9]/g, '_');
    
    return `${nameWithoutExt}_${timestamp}_${random}${extension}`;
  }

  /**
   * Read file as data URL (for previews)
   */
  static readAsDataURL(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  /**
   * Create object URL for preview (remember to revoke!)
   */
  static createObjectURL(file: File): string {
    return URL.createObjectURL(file);
  }

  /**
   * Revoke object URL
   */
  static revokeObjectURL(url: string): void {
    URL.revokeObjectURL(url);
  }
}