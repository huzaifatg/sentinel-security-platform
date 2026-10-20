"""Initial Sentinel identity, device, and telemetry schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("email", sa.String(320), nullable=False), sa.Column("password_hash", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.UniqueConstraint("email"))
    op.create_index("ix_users_email", "users", ["email"])
    op.create_table("devices", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("name", sa.String(120), nullable=False), sa.Column("serial_number", sa.String(120), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_devices_owner_id", "devices", ["owner_id"])
    op.create_index("ix_devices_serial_number", "devices", ["serial_number"])
    op.create_table("telemetry_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False), sa.Column("event_type", sa.String(80), nullable=False), sa.Column("payload", sa.Text(), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_telemetry_events_device_id", "telemetry_events", ["device_id"])


def downgrade() -> None:
    op.drop_table("telemetry_events")
    op.drop_table("devices")
    op.drop_table("users")
