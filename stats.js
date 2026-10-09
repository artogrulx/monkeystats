// api/stats.js
export default async function handler(req, res) {
  try {
    // The server reads the key securely from the .env file
    const apeKey = process.env.MONKEYTYPE_APE_KEY;

    const response = await fetch('https://monkeytype.com', {
      method: 'GET',
      headers: {
        'Authorization': `ApeKey ${apeKey}`
      }
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch from Monkeytype' });
    }

    const data = await response.json();
    
    // Send only the clean data back to your public website
    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
