import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:5000',
  timeout: 30000,
});

// Request interceptor for auth headers
api.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('institution_api_key');
  const adminKey = localStorage.getItem('admin_key');
  
  if (apiKey && config.url?.startsWith('/institution') || config.url === '/issue' || config.url === '/issue/batch' || config.url?.startsWith('/batch/')) {
    config.headers['X-API-Key'] = apiKey;
  }
  if (adminKey && config.url?.startsWith('/admin')) {
    config.headers['X-Admin-Key'] = adminKey;
  }
  
  return config;
});

// Institution APIs
export const getWallet = () => api.get('/institution/wallet');
export const issueCertificate = (formData) => api.post('/issue', formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
});
export const issueBatch = (formData) => api.post('/issue/batch', formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
});
export const getBatchStatus = (batchId) => api.get(`/batch/status/${batchId}`);

// Verification
export const verifyCertificate = (formData) => api.post('/verify', formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
});

// Artisan
export const registerArtisan = (data) => api.post('/register-artisan', data);
export const addArtwork = (formData) => api.post('/add-artwork', formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
});
export const getArtisan = (did) => api.get(`/artisan/${did}`);

// Payments (Domestic settlement — Razorpay)
export const createPaymentOrder = ({ artwork_id, collector_name, collector_email, buyer_name, buyer_email }) =>
  api.post('/api/payments/create-order', {
    artwork_id,
    collector_name: collector_name ?? buyer_name,
    collector_email: collector_email ?? buyer_email,
  });

export const verifyPayment = ({ razorpay_order_id, razorpay_payment_id, razorpay_signature, artwork_id }) =>
  api.post('/api/payments/verify-payment', {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    artwork_id,
  });

// Artwork object (provenance-first)
export const getArtwork = (artworkId) => api.get(`/api/artworks/${artworkId}`);

// Admin
export const getPendingArtisans = () => api.get('/admin/artisans/pending');
export const approveArtisan = (id) => api.post(`/admin/approve-artisan/${id}`);
export const rejectArtisan = (id) => api.post(`/admin/reject-artisan/${id}`);

// DigiLocker
export const startDigiLocker = () => api.post('/digilocker/start');
export const verifyDigiLocker = () => api.post('/digilocker/verify');
export const bindDigiLocker = () => api.post('/digilocker/bind');

export default api;