"""risk engine v2: security controls, persisted assessments, simulation details

Revision ID: 0003_risk_engine_v2
Revises: 0002_phase4
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_risk_engine_v2"
down_revision = "0002_phase4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing rows receive "{}" which the engine interprets as every control "unknown".
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("account_controls", sa.Text(), nullable=False, server_default="{}"))
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("security_controls", sa.Text(), nullable=False, server_default="{}"))
    # Legacy simulation rows keep NULL device_id/details and remain readable.
    with op.batch_alter_table("simulation_records") as batch:
        batch.add_column(sa.Column("device_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("details", sa.Text(), nullable=True))
        batch.create_foreign_key("fk_simulation_records_device_id", "devices", ["device_id"], ["id"], ondelete="CASCADE")
        batch.create_index("ix_simulation_records_device_id", ["device_id"])
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("methodology_version", sa.String(40), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("security_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("coverage", sa.Integer(), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_risk_assessments_owner_id", "risk_assessments", ["owner_id"])
    op.create_index("ix_risk_assessments_device_id", "risk_assessments", ["device_id"])


def downgrade() -> None:
    op.drop_table("risk_assessments")
    with op.batch_alter_table("simulation_records") as batch:
        batch.drop_index("ix_simulation_records_device_id")
        batch.drop_constraint("fk_simulation_records_device_id", type_="foreignkey")
        batch.drop_column("details")
        batch.drop_column("device_id")
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("security_controls")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("account_controls")
