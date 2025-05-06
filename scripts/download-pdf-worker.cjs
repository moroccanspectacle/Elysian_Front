const fs = require('fs');
const path = require('path');
const https = require('https');

// Create public directory if it doesn't exist
const publicDir = path.join(__dirname, '..', 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
  console.log('Created public directory');
}

// The target file path
const targetFile = path.join(publicDir, 'pdf.worker.min.js');

// Get the PDF.js version from package.json
let pdfjsVersion;
try {
  // Try to get the version from the installed package
  const packagePath = path.join(__dirname, '..', 'node_modules', 'pdfjs-dist', 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  pdfjsVersion = packageJson.version;
  console.log(`Detected PDF.js version: ${pdfjsVersion}`);
} catch (err) {
  // Fallback to a compatible version
  pdfjsVersion = '5.0.375';
  console.log(`Using fallback PDF.js version: ${pdfjsVersion}`);
}

// Worker URL based on detected version
const workerUrl = `https://unpkg.com/pdfjs-dist@${pdfjsVersion}/build/pdf.worker.min.js`;

console.log(`Downloading PDF.js worker from: ${workerUrl}`);

// Download the file
const file = fs.createWriteStream(targetFile);
https.get(workerUrl, (response) => {
  if (response.statusCode !== 200) {
    console.error(`Failed to download: ${response.statusCode} ${response.statusMessage}`);
    fs.unlinkSync(targetFile); // Clean up the file
    process.exit(1);
    return;
  }
  
  response.pipe(file);
  
  file.on('finish', () => {
    file.close();
    console.log(`Successfully downloaded PDF.js worker to: ${targetFile}`);
  });
}).on('error', (err) => {
  fs.unlinkSync(targetFile); // Clean up the file
  console.error(`Error downloading PDF.js worker: ${err.message}`);
  process.exit(1);
});