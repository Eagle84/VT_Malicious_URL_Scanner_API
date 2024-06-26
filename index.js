require("dotenv").config();
const axios = require("axios");

const apiKey = process.env.VIRUSTOTAL_API_KEY;
const baseUrl = "https://www.virustotal.com/api/v3";

// List of URLs to scan
const urlsToScan = [
//   "http://houkadaigakuin.com/css/webmail.konsoleh.co.za/emailSignIn_accountCUST_ID/konsoleh.sign_in/email.user/webmail.konsoleh.login.htm",
//   "http://muftizainulabideen.com/wp-admin/be/StandardV2/zyjviy2q=/",
//   "http://pilatesboutique.com.au/css/commlog/",
  "https://bit.ly/45JqCvI"
];

// Function to scan a URL
async function scanUrl(url) {
  try {
    const response = await axios.post(`${baseUrl}/urls`, new URLSearchParams({ url }), {
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    const analysisId = response.data.data.id;
    console.log("URL Scan ID:", analysisId);
    return analysisId;
  } catch (error) {
    console.error("Error scanning URL:", error);
    return null;
  }
}

// Function to get the scan report
async function getScanReport(analysisId) {
  try {
    const response = await axios.get(`${baseUrl}/analyses/${analysisId}`, {
      headers: {
        "x-apikey": apiKey,
      },
    });

    const report = response.data.data.attributes;
    //console.log('Scan Report:', report);

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
  } catch (error) {
    console.error("Error retrieving scan report:", error);
  }
}

// Main function to scan all URLs
async function main() {
  for (const url of urlsToScan) {
    console.log(`Scanning URL: ${url}`);
    const analysisId = await scanUrl(url);
    if (analysisId) {
      await getScanReport(analysisId);
    }
  }
}

main();
