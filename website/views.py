from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from . import db
import json
from .models import Malware, Tool, Indicator, Relationship, Vulnerability
views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def home():
    return render_template("home.html", user=current_user)

@views.route('/view/<collection>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def view(collection):
    if request.method == 'GET':
        if collection not in ['relationship', 'malware', 'tool', 'indicator', 'vulnerability']:
            flash('Invalid collection')
            return redirect(url_for('views.home'))
        else:
            if collection == 'relationship':
                data = Relationship.query.all()
            elif collection == 'malware':
                data = Malware.query.all()
            elif collection == 'tool':
                data = Tool.query.all()
            elif collection == 'indicator':
                data = Indicator.query.all()
            elif collection == 'vulnerability':
                data = Vulnerability.query.all()
            return render_template("views.html", user=current_user, CollType=collection, data=data)

@views.route('/add/<collection>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def add(collection):
    if request.method == 'GET':
        if collection not in ['relationship', 'malware', 'tool', 'indicator', 'vulnerability']:
            flash('Invalid collection!')
            return redirect(url_for('views.home'))
        else:
            if collection == 'relationship':
                colAttr=["Source", "Target", "Type"]
                if current_user.producer != 4:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'malware':
                colAttr = ["Name", "Type", "Creation Date", "Last Modified"]
                if current_user.producer != 1:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'tool':
                colAttr = ["Name", "Label", "Creation Date"]
                if current_user.producer != 2:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'indicator':
                colAttr = ["Indicator", "Creation Date"]
                if current_user.producer != 3:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'vulnerability':
                colAttr = ["CVE ID"]
                if current_user.producer != 5:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            return render_template("add.html", user=current_user, Collection=collection, ColAttr=colAttr)
    if request.method == 'POST':
        if collection == 'relationship':
            if current_user.producer != 4:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            source = request.form.get("Source")
            target = request.form.get("Target")
            type = request.form.get("Type")
            rel = Relationship.query.filter_by(source=source, type=type, target=target).first()
            if rel:
                flash("Relationship already exists!")
            else:
                new_rel = Relationship(source=source, type=type, target=target)
                db.session.add(new_rel)
                db.session.commit()
                flash("Relationship created successfully!")
                return redirect(url_for('views.home'))
        elif collection == 'malware':
            if current_user.producer != 1:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            name = request.form.get("Name")
            type = request.form.get("Type")
            creationDate = request.form.get("Creation Date")
            lastModified = request.form.get("Last Modified")
            mal = Malware.query.filter_by(name=name, type=type, creationDate=creationDate, lastModified=lastModified).first()
            if mal:
                flash("Malware already exists!")
            else:
                new_mal = Malware(name=name, type=type, creationDate=creationDate, lastModified=lastModified)
                db.session.add(new_mal)
                db.session.commit()
                flash("Malware added successfully!")
                return redirect(url_for('views.home'))
        elif collection == 'tool':
            if current_user.producer != 2:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            name = request.form.get("Name")
            label = request.form.get("Label")
            creationDate = request.form.get("Creation Date")
            tool = Tool.query.filter_by(name=name, whatItDoes=label, creationDate=creationDate)
            if tool:
                flash("Tool already exists!")
            else:
                new_tool = Tool(name=name, whatItDoes=label, creationDate=creationDate)
                db.session.add(new_tool)
                db.session.commit()
                flash("Tool added successfully!")
                return redirect(url_for('views.home'))
        elif collection == 'indicator':
            if current_user.producer != 3:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            indicator = request.form.get("Indicator")
            creationDate = request.form.get("Creation Date")
            ind = Indicator.query.filter_by(indicator=indicator, creationDate=creationDate).first()
            if ind:
                flash("Indicator already exists!")
            else:
                new_ind = Indicator(indicator=indicator, creationDate=creationDate)
                db.session.add(new_ind)
                db.session.commit()
                flash("Indicator added successfully!")
                return redirect(url_for('views.home'))
        elif collection == 'vulnerability':
            if current_user.producer != 5:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            id = request.form.get("CVE ID")
            vuln = Vulnerability.query.filter_by(cve_id=id).first()
            if vuln:
                flash("Vulnerability already exists!")
            else:
                new_vuln = Vulnerability(cve_id=id)
                db.session.add(new_vuln)
                db.session.commit()
                flash("Vulnerability added successfully!")
                return redirect(url_for('views.home'))


@views.route('/delete/<collectio>/<collID>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def delete(collection, collID):
    if collection not in ['relationship', 'malware', 'tool', 'indicator', 'vulnerability']:
            flash('Invalid collection!')
            return redirect(url_for('views.home'))
        else:
            if collection == 'relationship':
                if current_user.producer != 4:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'malware':
                if current_user.producer != 1:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'tool':
                if current_user.producer != 2:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'indicator':
                if current_user.producer != 3:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))
            elif collection == 'vulnerability':
                if current_user.producer != 5:
                    flash('You don\'t have to rights to access this page!')
                    return redirect(url_for('views.home'))


        

@views.route('/update/<collection>/', methods=['GET', 'POST', 'PUT', 'DELETE'])
def update(collection):
    #




