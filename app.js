// mock-hospital.js
import express from 'express'
import dotenv from 'dotenv'
dotenv.config();

const app = express();
app.use(express.json());
app.get('/api/hospitals/:id', (req, res) => {
  if (req.headers['x-service-key'] !== process.env.SERVICE_KEY) {
    return res.status(401).json({ message: 'Invalid service key' });
  }
  res.json({ hospital: { id: req.params.id, name: 'Mock Hospital' } });
});
app.listen(8090, () => console.log('Mock Hospital Service on 8080'));