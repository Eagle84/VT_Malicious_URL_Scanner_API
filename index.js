require("dotenv").config();
const axios = require("axios");

const apiKey = process.env.VIRUSTOTAL_API_KEY;
const baseUrl = "https://www.virustotal.com/api/v3";

// List of URLs to scan
const urlsToScan = [
  "https://bit.ly/45JqCvI",
  "https://kyc-bltflyer.web.app/"
];

const rateLimit = 4; // 4 lookups per minute
const delayBetweenRequests = 60000 / rateLimit; // Delay between requests in milliseconds

// Function to scan a URL
async function scanUrl(url) {
  let retries = 3; // Number of retries for each request

  while (retries > 0) {
    try {
      const response = await axios.post(`${baseUrl}/urls`, new URLSearchParams({ url }), {
        headers: {
          "x-apikey": apiKey,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: 10000 // 10 seconds timeout
      });

      const analysisId = response.data.data.id;
      console.log("URL Scan ID:", analysisId);
      return analysisId;
    } catch (error) {
      if (error.code === 'ECONNABORTED') {
        console.error("Request timed out, retrying...");
      } else {
        console.error("Error scanning URL:", error.message);
        return null;
      }
      retries -= 1;
      await new Promise(resolve => setTimeout(resolve, delayBetweenRequests)); // Wait before retrying
    }
  }

  return null;
}

// Function to get the scan report
async function getScanReport(analysisId) {
  let retries = 3; // Number of retries for each request

  while (retries > 0) {
    try {
      const response = await axios.get(`${baseUrl}/analyses/${analysisId}`, {
        headers: {
          "x-apikey": apiKey,
        },
        timeout: 10000 // 10 seconds timeout
      });

      const report = response.data.data.attributes;

      // Analyze the scan report
      const maliciousCount = report.stats.malicious;
      const suspiciousCount = report.stats.suspicious;
      const harmlessCount = report.stats.harmless;
      const undetectedCount = report.stats.undetected;

      console.log(`Malicious: ${maliciousCount}, Suspicious: ${suspiciousCount}, Harmless: ${harmlessCount}, Undetected: ${undetectedCount}`);

      if (maliciousCount > 0) {
        console.log("The URL is malicious.");
      } else if (suspiciousCount > 0) {
        console.log("The URL is suspicious.");
      } else {
        console.log("The URL is good.");
      }
      return;
    } catch (error) {
      if (error.code === 'ECONNABORTED') {
        console.error("Request timed out, retrying...");
      } else {
        console.error("Error retrieving scan report:", error.message);
      }
      retries -= 1;
      await new Promise(resolve => setTimeout(resolve, delayBetweenRequests)); // Wait before retrying
    }
  }
}

// Main function to scan all URLs
async function main() {
  for (const url of urlsToScan) {
    console.log(`Scanning URL: ${url}`);
    const analysisId = await scanUrl(url);
    if (analysisId) {
      await new Promise(resolve => setTimeout(resolve, delayBetweenRequests)); // Wait to respect rate limit
      await getScanReport(analysisId);
      await new Promise(resolve => setTimeout(resolve, delayBetweenRequests)); // Wait to respect rate limit
    }
  }
}

main();
