from flask import Blueprint, jsonify, request
from sqlalchemy import desc, func
from models import Product, Vulnerability, AffectedVersionsNumber
from database import db
from datetime import datetime


bp = Blueprint('api', __name__, url_prefix='/api')


@bp.route('/critical_vulnerabilities', methods=['GET'])
def get_critical_vulnerabilities():
    # Retrieve software and version combinations with critical vulnerabilities.
    # The time range is defined using query parameters 'from' and 'to', for example: /critical_vulnerabilities?from=2023-01-01&to=2023-06-30
    # The cvss range is defined using query parameters 'cvss_min' and 'cvss_max', for example: /critical_vulnerabilities?cvss_min=1.0&cvss_max=7.0
    # The specific product and vendor are defined using query parameters 'product' and 'vendor', for example: /critical_vulnerabilities?product=apache&vendor=apache

    cvss_min = request.args.get('cvss_min', default=0.0, type=float)
    cvss_max = request.args.get('cvss_max', default=10.0, type=float)

    product = request.args.get('product', default=None, type=str)
    vendor = request.args.get('vendor', default=None, type=str)

    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')

    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max

    query = (
        db.session.query(
            Product.product,
            Product.vendor,
            func.group_concat(Product.version).label('versions'),
            Vulnerability.vulnerability_types,
            Vulnerability.cvss_score,
            Vulnerability.last_update_date
        )
        .join(AffectedVersionsNumber, Product.affected_versions_number_id == AffectedVersionsNumber.id)
        .join(Vulnerability, AffectedVersionsNumber.vulnerability_id == Vulnerability.id)
        .filter(Vulnerability.cvss_score >= cvss_min)
        .filter(Vulnerability.cvss_score <= cvss_max)
        .filter(Vulnerability.last_update_date >= from_date)
        .filter(Vulnerability.last_update_date <= to_date)
    )

    if product:
        query = query.filter(Product.product == product)

    if vendor:
        query = query.filter(Product.vendor == vendor)

    results = query.group_by(Product.product, Product.vendor,
                             Vulnerability.vulnerability_types, Vulnerability.cvss_score).limit(100).all()
    formatted_results = [
        {
            'product': product,
            'vendor': vendor,
            'versions': versions.split(','),
            'vulnerability_types': vulnerability_types,
            'cvss_score': cvss_score,
            'date': date.strftime('%Y-%m-%d'),
        }
        for product, vendor, versions, vulnerability_types, cvss_score, date in results
    ]
    return jsonify(formatted_results)


@bp.route('/software_updates', methods=['GET'])
def get_software_updates():
    # Retrieve software with critical vulnerabilities that require an update.
    # The time range is defined using query parameters 'from' and 'to', for example: /software_updates?from=2023-01-01&to=2023-06-30
    # The cvss range is defined using query parameters 'cvss_min' and 'cvss_max', for example: /software_updates?cvss_min=1.0&cvss_max=7.0
    # It's hard to define what software we should return. I decided to check
    # if the updates were provided to the product after the bug was discovered.

    cvss_min = request.args.get('cvss_min', default=0.0, type=float)
    cvss_max = request.args.get('cvss_max', default=10.0, type=float)

    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')

    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max

    results = (
        db.session.query(
            Product.product,
            Product.vendor,
            func.group_concat(Product.version).label('versions'),
            func.group_concat(Product.update).label('updates'),
            Vulnerability.last_update_date
        )
        .join(AffectedVersionsNumber, Product.affected_versions_number_id == AffectedVersionsNumber.id)
        .join(Vulnerability, AffectedVersionsNumber.vulnerability_id == Vulnerability.id)
        .filter(Vulnerability.cvss_score >= cvss_min)
        .filter(Vulnerability.cvss_score <= cvss_max)
        .filter(Vulnerability.last_update_date >= from_date)
        .filter(Vulnerability.last_update_date <= to_date)
        .filter(
            (Product.update != '') &
            (Product.update != '*') &
            (Product.update != '-'))
        # Check if the update field is not empty, "*" or "-", also other values may be used
        # to indicate that the product is not updated ->
        # TODO: EDA needed
        .group_by(Product.product, Product.vendor)
        .limit(100)
        .all()
    )

    formatted_results = [
        {
            'product': product,
            'vendor': vendor,
            'versions': versions.split(','),
            'updates': updates.split(','),
            'date': date.strftime('%Y-%m-%d'),
        }
        for product, vendor, versions, updates, date in results
    ]
    return jsonify(formatted_results)


@bp.route('/bug_count_by_type', methods=['GET'])
def get_bug_count_by_type():
    # Retrieve the number of bugs grouped by vulnerability type within a specified time range.
    # The time range is defined using query parameters 'from' and 'to', for example: /bug_count_by_type?from=2023-01-01&to=2023-06-30
    # The cvss range is defined using query parameters 'cvss_min' and 'cvss_max', for example: /bug_count_by_type?cvss_min=1.0&cvss_max=7.0

    cvss_min = request.args.get('cvss_min', default=0.0, type=float)
    cvss_max = request.args.get('cvss_max', default=10.0, type=float)

    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')

    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max

    results = (
        db.session.query(
            Vulnerability.vulnerability_types,
            func.count(Vulnerability.id).label('bug_count')
        )
        .filter(Vulnerability.cvss_score >= cvss_min)
        .filter(Vulnerability.cvss_score <= cvss_max)
        .filter(Vulnerability.vulnerability_types != "")
        .filter(Vulnerability.last_update_date >= from_date, Vulnerability.last_update_date <= to_date)
        .group_by(Vulnerability.vulnerability_types)
        .order_by(desc('bug_count'))
        .all()
    )

    bug_count_by_type = [
        {
            'vulnerability_type': result[0],
            'bug_count': result[1]
        }
        for result in results
    ]

    return jsonify(bug_count_by_type)


@bp.route('/recent_vulnerable_codes', methods=['GET'])
def get_recent_vulnerable_codes():
    # The time range is defined using query parameters 'from' and 'to', for example: /recent_vulnerable_codes?from=2023-01-01&to=2023-06-30
    # The cvss range is defined using query parameters 'cvss_min' and 'cvss_max', for example: /recent_vulnerable_codes?cvss_min=1.0&cvss_max=7.0

    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')
    cvss_min = request.args.get('cvss_min', default=0.0, type=float)
    cvss_max = request.args.get('cvss_max', default=10.0, type=float)

    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max

    results = (
        db.session.query(
            Product.product,
            Product.vendor,
            Product.product_type,
            func.count(Vulnerability.id).label('vulnerability_count')
        )
        .join(AffectedVersionsNumber, Product.affected_versions_number_id == AffectedVersionsNumber.id)
        .join(Vulnerability, AffectedVersionsNumber.vulnerability_id == Vulnerability.id)
        .filter(Vulnerability.cvss_score >= cvss_min)
        .filter(Vulnerability.cvss_score <= cvss_max)
        .filter(Vulnerability.publish_date >= from_date)
        .filter(Vulnerability.publish_date <= to_date)
        .group_by(Product.product, Product.vendor)
        .order_by(desc('vulnerability_count'))
        .limit(100)
        .all()
    )

    formatted_results = [
        {
            'product': product,
            'vendor': vendor,
            "type": type,
            'vulnerability_count': vulnerability_count
        }
        for product, vendor, type, vulnerability_count in results
    ]
    return jsonify(formatted_results)


@bp.route('/products_with_critical_vulnerabilities', methods=['GET'])
def get_products_with_critical_vulnerabilities():
    # The time range is defined using query parameters 'from' and 'to', for example: /products_with_critical_vulnerabilities?from=2023-01-01&to=2023-06-30
    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')
    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max
    results = (
        db.session.query(
            Product.product,
            Product.vendor,
            Vulnerability.cvss_score
        )
        .join(AffectedVersionsNumber, Product.affected_versions_number_id == AffectedVersionsNumber.id)
        .join(Vulnerability, AffectedVersionsNumber.vulnerability_id == Vulnerability.id)
        .filter(Vulnerability.cvss_score > 9.0)
        .filter(Vulnerability.publish_date >= from_date)
        .filter(Vulnerability.publish_date <= to_date)
        .all()
    )

    formatted_results = [
        {
            'product': product,
            'vendor': vendor,
            'cvss_score': cvss_score
        }
        for product, vendor, cvss_score in results
    ]

    return jsonify(formatted_results)


@bp.route('/vulnerability_severity_statistics', methods=['GET'])
def get_vulnerability_severity_statistics():
    # This API provides statistical information about the severity levels of vulnerabilities in the database.
    # The time range is defined using query parameters 'from' and 'to', for example: /vulnerability_severity_statistics?from=2023-01-01&to=2023-06-30
    # The cvss range is defined using query parameters 'cvss_min' and 'cvss_max', for example: /critical_vulnerabilities?cvss_min=1.0&cvss_max=7.0
    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')
    cvss_min = request.args.get('cvss_min', default=0.0, type=float)
    cvss_max = request.args.get('cvss_max', default=10.0, type=float)

    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max
    results = (
        db.session.query(
            Vulnerability.confidentiality_impact,
            Vulnerability.integrity_impact,
            Vulnerability.availability_impact,
            func.count(Vulnerability.id).label('vulnerability_count')
        )
        .filter(Vulnerability.cvss_score >= cvss_min)
        .filter(Vulnerability.cvss_score <= cvss_max)
        .filter(Vulnerability.publish_date >= from_date)
        .filter(Vulnerability.publish_date <= to_date)
        .filter(
            (Vulnerability.availability_impact != "") &
            (Vulnerability.availability_impact != "???") &
            (Vulnerability.integrity_impact != "") &
            (Vulnerability.integrity_impact != "???") &
            (Vulnerability.confidentiality_impact != "") &
            (Vulnerability.confidentiality_impact != "???")
        )
        .group_by(
            Vulnerability.confidentiality_impact,
            Vulnerability.integrity_impact,
            Vulnerability.availability_impact
        )
        .all()
    )

    formatted_results = [
        {
            'confidentiality_impact': confidentiality_impact,
            'integrity_impact': integrity_impact,
            'availability_impact': availability_impact,
            'vulnerability_count': vulnerability_count
        }
        for confidentiality_impact, integrity_impact, availability_impact, vulnerability_count in results
    ]

    return jsonify(formatted_results)


@bp.route('/top_vendors_most_vulnerabilities', methods=['GET'])
def get_top_vendors_most_vulnerabilities():
    # This API retrieves a list of vendors that produce the most buggy
    # software based on the number of vulnerabilities associated with their products
    # The time range is defined using query parameters 'from' and 'to', for example: /top_vendors_most_vulnerabilities?from=2023-01-01&to=2023-06-30
    # The cvss range is defined using query parameters 'cvss_min' and 'cvss_max', for example: /top_vendors_most_vulnerabilities?cvss_min=1.0&cvss_max=7.0

    cvss_min = request.args.get('cvss_min', default=0.0, type=float)
    cvss_max = request.args.get('cvss_max', default=10.0, type=float)

    from_date_str = request.args.get('from')
    to_date_str = request.args.get('to')

    if from_date_str:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
    else:
        from_date = datetime.min

    if to_date_str:
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
    else:
        to_date = datetime.max
    results = (
        db.session.query(
            Product.vendor,
            func.count(Vulnerability.id).label('vulnerability_count')
        )
        .join(AffectedVersionsNumber, Product.affected_versions_number_id == AffectedVersionsNumber.id)
        .join(Vulnerability, AffectedVersionsNumber.vulnerability_id == Vulnerability.id)
        .filter(Vulnerability.cvss_score >= cvss_min)
        .filter(Vulnerability.cvss_score <= cvss_max)
        .filter(Vulnerability.publish_date >= from_date)
        .filter(Vulnerability.publish_date <= to_date)
        .group_by(Product.vendor)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
        .all()
    )

    formatted_results = [
        {
            'vendor': vendor,
            'vulnerability_count': vulnerability_count
        }
        for vendor, vulnerability_count in results
    ]

    return jsonify(formatted_results)
