const fs = require('fs');
const path = require('path');

// Create public directory if it doesn't exist
const publicDir = path.join(__dirname, '..', 'public');
try {
  if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
    console.log('Created public directory');
  }
  
  // Check multiple potential locations for the PDF worker file
  const possiblePaths = [
    // Check v5.x path
    path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'webpack', 'pdf.worker.js'),
    path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'webpack', 'pdf.worker.min.js'),
    // Check v3.x and v4.x paths
    path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'build', 'pdf.worker.js'),
    path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'build', 'pdf.worker.min.js'),
    // Check v2.x paths
    path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'legacy', 'build', 'pdf.worker.js'),
    path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'legacy', 'build', 'pdf.worker.min.js'),
  ];

  // Find the first existing path
  let sourceFile = null;
  for (const filePath of possiblePaths) {
    if (fs.existsSync(filePath)) {
      sourceFile = filePath;
      break;
    }
  }

  if (!sourceFile) {
    throw new Error('Could not find PDF worker file in any of the expected locations');
  }
  
  const targetFile = path.join(publicDir, 'pdf.worker.min.js');
  
  fs.copyFileSync(sourceFile, targetFile);
  console.log(`Successfully copied PDF worker from "${sourceFile}" to "${targetFile}"`);
} catch (err) {
  console.error('Error copying PDF worker file:', err);
  process.exit(1);
}