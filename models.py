"""
Minimal Flask-SQLAlchemy models for the x402 acquisition MVP.
"""

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Artwork(db.Model):
    __tablename__ = "x402_artworks"

    id = db.Column(db.String(64), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    current_owner = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.String(32), nullable=False)


class ProvenanceEvent(db.Model):
    __tablename__ = "x402_provenance_events"

    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(
        db.String(64),
        db.ForeignKey("x402_artworks.id"),
        nullable=False,
        index=True,
    )
    owner_wallet = db.Column(db.String(255), nullable=False)
    event_type = db.Column(db.String(128), nullable=False)
    settlement_reference = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.String(32), nullable=False, index=True)

    artwork = db.relationship(
        "Artwork",
        backref=db.backref("provenance_events", lazy=True),
    )
