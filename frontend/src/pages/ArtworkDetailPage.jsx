import React, { useEffect, useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ShieldCheck, Fingerprint, ScrollText, ExternalLink } from "lucide-react";
import * as api from "../api/api";
import { useToast } from "../context/ToastContext";

const loadRazorpay = () =>
  new Promise((resolve) => {
    if (window.Razorpay) return resolve(true);
    const script = document.createElement("script");
    script.src = "https://checkout.razorpay.com/v1/checkout.js";
    script.onload = () => resolve(true);
    script.onerror = () => resolve(false);
    document.body.appendChild(script);
  });

export const ArtworkDetailPage = () => {
  const { artworkId } = useParams();
  const { addToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [artwork, setArtwork] = useState(null);
  const [provenance, setProvenance] = useState([]);
  const [ownership, setOwnership] = useState(null);
  const [collector, setCollector] = useState({ name: "", email: "" });
  const [acquiring, setAcquiring] = useState(false);

  const id = useMemo(() => Number(artworkId), [artworkId]);

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      try {
        setLoading(true);
        const { data } = await api.getArtwork(id);
        if (!mounted) return;
        setArtwork(data.artwork);
        setProvenance(data.provenance_events || []);
        setOwnership(data.ownership || null);
      } catch (e) {
        addToast("Could not load artwork record", "error");
      } finally {
        if (mounted) setLoading(false);
      }
    };
    if (Number.isFinite(id)) run();
    return () => {
      mounted = false;
    };
  }, [id, addToast]);

  const handleAcquire = async () => {
    try {
      if (!collector.name.trim() || !collector.email.trim()) {
        addToast("Collector name and email are required to record acquisition", "error");
        return;
      }
      setAcquiring(true);
      const ok = await loadRazorpay();
      if (!ok) {
        addToast("Could not initialize acquisition flow", "error");
        return;
      }

      const { data } = await api.createPaymentOrder({
        artwork_id: id,
        collector_name: collector.name,
        collector_email: collector.email,
      });
      if (!data?.success) {
        addToast("Could not prepare acquisition", "error");
        return;
      }

      const options = {
        key: data.key_id,
        amount: data.amount,
        currency: data.currency,
        name: "SkillChain",
        description: "Acquire authenticated cultural work",
        order_id: data.order_id,
        method: { upi: true },
        prefill: { name: collector.name, email: collector.email },
        theme: { color: "#B56A3E" },
        handler: async (resp) => {
          const verify = await api.verifyPayment({
            razorpay_order_id: resp.razorpay_order_id,
            razorpay_payment_id: resp.razorpay_payment_id,
            razorpay_signature: resp.razorpay_signature,
            artwork_id: id,
          });
          if (verify?.data?.success) {
            addToast("Acquisition Recorded • Provenance Updated", "success");
            const refreshed = await api.getArtwork(id);
            setProvenance(refreshed.data.provenance_events || []);
            setOwnership(refreshed.data.ownership || null);
          } else {
            addToast("Settlement received, but verification failed", "error");
          }
        },
      };

      const rzp = new window.Razorpay(options);
      rzp.open();
    } catch (e) {
      addToast("Acquisition flow failed", "error");
    } finally {
      setAcquiring(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] px-6 pt-24">
        <div className="max-w-5xl mx-auto text-[#6D5646]">Preparing provenance object…</div>
      </div>
    );
  }

  if (!artwork) {
    return (
      <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] px-6 pt-24">
        <div className="max-w-5xl mx-auto">
          <p className="text-[#6D5646]">This artwork record could not be resolved.</p>
          <Link to="/verify" className="text-[#B56A3E] hover:underline">
            Return to verification
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] overflow-hidden">
      <section className="relative px-6 pt-24 pb-10 border-b border-[#d8c7ab] overflow-hidden">
        <div className="absolute inset-0 opacity-[0.05] bg-[url('https://www.transparenttextures.com/patterns/old-map.png')]" />
        <div className="relative max-w-6xl mx-auto grid lg:grid-cols-[1.1fr_0.9fr] gap-10">
          <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] overflow-hidden">
            <div className="aspect-[4/3] bg-[#eadcc5] flex items-center justify-center text-[#8B694D]">
              Artwork preview
            </div>
            <div className="p-7">
              <h1 className="text-4xl font-serif mb-2">{artwork.title || "Untitled work"}</h1>
              <p className="text-[#6D5646] mb-4">{artwork.description || "A recorded work in the SkillChain archive."}</p>
              <div className="grid sm:grid-cols-2 gap-3 text-sm">
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <Fingerprint size={14} /> Artist DID
                  </div>
                  <div className="mt-2 font-mono break-all text-xs">{artwork.artisan_did}</div>
                </div>
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <ShieldCheck size={14} /> Status
                  </div>
                  <div className="mt-2">{artwork.status || "archived"}</div>
                </div>
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <ScrollText size={14} /> IPFS CID
                  </div>
                  <div className="mt-2 font-mono break-all text-xs">{artwork.ipfs_cid || "—"}</div>
                </div>
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <ExternalLink size={14} /> Chain Anchor
                  </div>
                  {artwork.tx_id ? (
                    <a
                      className="mt-2 inline-flex items-center gap-1 text-[#B56A3E] hover:underline"
                      href={`https://algoexplorer.io/tx/${artwork.tx_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View transaction <ExternalLink size={12} />
                    </a>
                  ) : (
                    <div className="mt-2">—</div>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-7">
              <h2 className="text-2xl font-serif mb-2">Acquire Artwork</h2>
              <p className="text-sm text-[#6D5646] mb-4">
                Settlement confirmation becomes an archival provenance event. Ownership is recorded only after server verification.
              </p>
              {ownership?.owner_name ? (
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa] text-sm text-[#6D5646] mb-4">
                  Current ownership snapshot: <span className="text-[#2B1D16]">{ownership.owner_name}</span>
                </div>
              ) : null}
              <div className="grid gap-3">
                <input
                  className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                  placeholder="Collector name"
                  value={collector.name}
                  onChange={(e) => setCollector((c) => ({ ...c, name: e.target.value }))}
                />
                <input
                  className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                  placeholder="Collector email"
                  value={collector.email}
                  onChange={(e) => setCollector((c) => ({ ...c, email: e.target.value }))}
                />
                <button
                  onClick={handleAcquire}
                  disabled={acquiring}
                  className="bg-[#1C1A16] hover:bg-black transition duration-300 text-[#F7F0E1] py-4 px-6 tracking-wide shadow-xl disabled:opacity-50"
                >
                  {acquiring ? "Preparing acquisition…" : "Acquire Artwork"}
                </button>
              </div>
              <p className="text-xs text-[#8B694D] mt-3 uppercase tracking-[0.18em]">
                Acquisition is recorded, never overwritten.
              </p>
            </div>

            <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-7">
              <h2 className="text-2xl font-serif mb-4">Provenance Timeline</h2>
              <div className="space-y-3">
                {provenance.length === 0 ? (
                  <div className="text-sm text-[#6D5646]">No events yet.</div>
                ) : (
                  provenance.map((ev) => (
                    <div key={ev.id} className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                      <div className="flex items-center justify-between">
                        <div className="text-xs uppercase tracking-[0.18em] text-[#8B694D]">
                          {ev.provenance_event_type || ev.event_type}
                        </div>
                        <div className="text-xs text-[#6D5646]">{ev.created_at}</div>
                      </div>
                      <div className="mt-2 text-sm text-[#2B1D16] break-words">{ev.event_type}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

