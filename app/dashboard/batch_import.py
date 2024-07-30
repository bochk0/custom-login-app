import arrow
from flask import render_template, flash, request, redirect, url_for
from flask_login import login_required, current_user

from app import s3
from app.config import JOB_BATCH_IMPORT
from app.dashboard.base import dashboard_bp
from app.dashboard.views.enter_sudo import sudo_required
from app.db import Session
from app.extensions import limiter
from app.log import LOG
from app.models import File, BatchImport, Job
from app.utils import random_string, CSRFValidationForm


@dashboard_bp.route("/batch_import", methods=["GET", "POST"])
@login_required
@sudo_required
@limiter.limit("10/minute", methods=["POST"])
def batch_import_route():
    # only for users who have custom domains
    if not current_user.verified_custom_domains():
        flash("Alias batch import is only available for custom domains", "warning")

    if current_user.disable_import:
        flash(
            "you cannot use the import feature, please contact Login team",
            "error",
        )
        return redirect(url_for("dashboard.index"))

    batch_imports = BatchImport.filter_by(
        user_id=current_user.id, processed=False
    ).all()

    csrf_form = CSRFValidationForm()

    if request.method == "POST":
        if not csrf_form.validate():
            flash("Invalid request", "warning")
            return redirect(request.url)
        if len(batch_imports) > 10:
            flash(
                "You have too many imports already. Please wait until some get cleaned up",
                "error",
            )
            return render_template(
                "dashboard/batch_import.html",
                batch_imports=batch_imports,
                csrf_form=csrf_form,
            )


        # Schedule batch import job
        Job.create(
            name=JOB_BATCH_IMPORT,
            payload={"batch_import_id": bi.id},
            run_at=arrow.now(),
        )
        Session.commit()

        flash(
            "The file has been uploaded successfully and the import will start shortly",
            "success",
        )

        return redirect(url_for("dashboard.batch_import_route"))

    return render_template(
        "dashboard/batch_import.html", batch_imports=batch_imports, csrf_form=csrf_form
    )
