"""phase 4 anomaly and simulation records

Revision ID: 0002_phase4
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_phase4"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("anomaly_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False), sa.Column("features", sa.Text(), nullable=False), sa.Column("source", sa.String(20), nullable=False), sa.Column("is_anomaly", sa.Boolean(), nullable=False), sa.Column("score", sa.Float(), nullable=False), sa.Column("explanation", sa.Text(), nullable=False), sa.Column("model_version", sa.String(80), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_anomaly_events_owner_id", "anomaly_events", ["owner_id"])
    op.create_index("ix_anomaly_events_device_id", "anomaly_events", ["device_id"])
    op.create_table("simulation_records", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("asset_id", sa.String(120), nullable=False), sa.Column("before_risk_score", sa.Integer(), nullable=False), sa.Column("after_risk_score", sa.Integer(), nullable=False), sa.Column("before_security_score", sa.Integer(), nullable=False), sa.Column("after_security_score", sa.Integer(), nullable=False), sa.Column("removed_findings", sa.Text(), nullable=False), sa.Column("added_findings", sa.Text(), nullable=False), sa.Column("explanation", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_simulation_records_owner_id", "simulation_records", ["owner_id"])


def downgrade() -> None:
    op.drop_table("simulation_records")
    op.drop_table("anomaly_events")
