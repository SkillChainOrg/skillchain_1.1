import { BrowserRouter, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import { VerificationPage } from "./pages/VerificationPage";
import { ArtisanDashboard } from "./pages/ArtisanDashboard";
import { ArtworkDetailPage } from "./pages/ArtworkDetailPage";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/verify" element={<VerificationPage />} />
        <Route path="/artisan" element={<ArtisanDashboard />} />
        <Route path="/artworks/:artworkId" element={<ArtworkDetailPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
