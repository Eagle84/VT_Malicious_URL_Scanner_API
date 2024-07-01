require("dotenv").config();
const mysql = require("mysql2/promise");
const axios = require("axios");
const fs = require("fs");
const { createObjectCsvWriter } = require("csv-writer");

const apiKey = process.env.VIRUSTOTAL_API_KEY;
const baseUrl = "https://www.virustotal.com/api/v3";
const dbConfig = {
  host: process.env.DB_HOST_TEST,
  user: process.env.DB_USER_TEST,
  password: process.env.DB_PASSWORD_TEST,
  database: process.env.DB_DATABASE_TEST,
  connectTimeout: 10000, // 10 seconds timeout
};

const rateLimit = 4; // 4 lookups per minute
const delayBetweenRequests = 60000 / rateLimit; // Delay between requests in milliseconds

// CSV Writer setup
const csvWriter = createObjectCsvWriter({
  path: "scan_results.csv",
  header: [
    { id: "url", title: "URL" },
    { id: "status", title: "Status" },
    { id: "scan_date", title: "Scan Date" },
    { id: "results", title: "Results" },
  ],
  append: true, // This will append to the file if it already exists
});

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
        timeout: 10000, // 10 seconds timeout
      });

      const analysisId = response.data.data.id;
      console.log("URL Scan ID:", analysisId);
      return analysisId;
    } catch (error) {
      if (error.code === "ECONNABORTED") {
        console.error("Request timed out, retrying...");
      } else {
        console.error("Error scanning URL:", error.message);
        return null;
      }
      retries -= 1;
      await new Promise((resolve) => setTimeout(resolve, delayBetweenRequests)); // Wait before retrying
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
        timeout: 10000, // 10 seconds timeout
      });

      const report = response.data.data.attributes;

      // Analyze the scan report
      const maliciousCount = report.stats.malicious;
      const suspiciousCount = report.stats.suspicious;
      const harmlessCount = report.stats.harmless;
      const undetectedCount = report.stats.undetected;

      console.log(`Malicious: ${maliciousCount}, Suspicious: ${suspiciousCount}, Harmless: ${harmlessCount}, Undetected: ${undetectedCount}`);

      if (maliciousCount > 0) {
        return "Malicious";
      } else if (suspiciousCount > 0) {
        return "Suspicious";
      } else {
        return "Good";
      }
    } catch (error) {
      if (error.code === "ECONNABORTED") {
        console.error("Request timed out, retrying...");
      } else {
        console.error("Error retrieving scan report:", error.message);
      }
      retries -= 1;
      await new Promise((resolve) => setTimeout(resolve, delayBetweenRequests)); // Wait before retrying
    }
  }

  return "Unknown";
}

// Main function to scan all URLs and export results to CSV
async function main() {
  let database;
  const scanDate = new Date().toISOString();
  try {
    database = await mysql.createConnection(dbConfig);

    // Fetch URLs from the database
    const [companyHomepageResults] = await database.query(`SELECT homepage FROM New_Company WHERE homepage IS NOT NULL`);
    const [newsUrlsResults] = await database.query(`SELECT news_url FROM News WHERE news_url IS NOT NULL`);

    // Combine and de-duplicate URLs
    const urlsToScan = Array.from(new Set([...companyHomepageResults.map((row) => row.homepage), ...newsUrlsResults.map((row) => row.news_url)]));

    for (const url of urlsToScan) {
      console.log(`Scanning URL: ${url}`);
      const analysisId = await scanUrl(url);
      let status = "Not Scanned";
      let result = "Unknown";
      if (analysisId) {
        await new Promise((resolve) => setTimeout(resolve, delayBetweenRequests)); // Wait to respect rate limit
        result = await getScanReport(analysisId);
        status = "Scanned";
        await new Promise((resolve) => setTimeout(resolve, delayBetweenRequests)); // Wait to respect rate limit
      }
      const record = { url, status, scan_date: scanDate, results: result };
      await csvWriter.writeRecords([record]); // Append each result to the CSV file
    }

    console.log("Scan results have been written to scan_results.csv");
  } catch (error) {
    console.error("Error in main function:", error);
  } finally {
    // Close the database connection
    if (database) {
      await database.end();
    }
  }
}

main();
