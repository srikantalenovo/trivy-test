from flask import Flask, render_template, request
import pandas as pd
import os
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# File name mappings
SCAN_TYPES = {
    'cve': {
        'master': 'master-output.csv',
        'feature': 'feature-output.csv',
        'dev': 'dev-output.csv'
    },
    'ut': {
        'master': 'master-ut-output.csv',
        'feature': 'feature-ut-output.csv',
        'dev': 'dev-ut-output.csv'
    }
}

def process_csv_data(csv_file, scan_type):
    try:
        if not os.path.exists(csv_file):
            return None, f"File '{csv_file}' not found"
        
        if os.path.getsize(csv_file) == 0:
            return None, f"File '{csv_file}' is empty"

        # Try reading CSV with multiple fallback options
        df = None
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
        delimiters = [',', ';', '\t']
        
        for encoding in encodings:
            for delimiter in delimiters:
                try:
                    df = pd.read_csv(
                        csv_file,
                        encoding=encoding,
                        delimiter=delimiter,
                        on_bad_lines='warn',
                        skipinitialspace=True,
                        quotechar='"'
                    )
                    if not df.empty:
                        break
                except:
                    continue
            if df is not None and not df.empty:
                break

        if df is None or df.empty:
            return None, "Could not read CSV file with any standard encoding/delimiter"

        # Standardize column names
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
        
        if scan_type == 'cve':
            return process_cve_data(df)
        else:
            return process_ut_data(df)

    except Exception as e:
        return None, f"Error processing CSV: {str(e)}"

def process_cve_data(df):
    # Define required and optional columns for CVE
    required_columns = ['image_name', 'severity', 'count']
    optional_columns = ['report_url', 'image_owner']
    
    # Check required columns
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        return None, f"Missing required columns: {', '.join(missing_columns)}"

    # Clean data
    df = df[required_columns + [col for col in optional_columns if col in df.columns]].copy()
    df = df.dropna(how='all')
    
    # Convert count to numeric
    df['count'] = pd.to_numeric(df['count'], errors='coerce')
    df = df.dropna(subset=['count'])
    
    if df.empty:
        return None, "No valid data after cleaning"

    # Group data by image name
    grouped_data = defaultdict(lambda: {
        'Critical': 0, 
        'High': 0, 
        'Medium': 0, 
        'Low': 0,
        'report_urls': set(),
        'image_owners': set()
    })
    
    for _, row in df.iterrows():
        image_name = str(row['image_name']).strip()
        severity = str(row['severity']).strip().capitalize()
        count = int(row['count'])
        
        if severity in grouped_data[image_name]:
            grouped_data[image_name][severity] += count
        
        if 'report_url' in row and pd.notna(row['report_url']):
            grouped_data[image_name]['report_urls'].add(str(row['report_url']).strip())
        
        if 'image_owner' in row and pd.notna(row['image_owner']):
            grouped_data[image_name]['image_owners'].add(str(row['image_owner']).strip())
    
    return grouped_data, None

def process_ut_data(df):
    # Define expected columns for UT data
    expected_columns = [
        'sl.no', 'reponame', 'owner', 'coverage', 'gate', 
        'pr_url', 'mode', 'date', 'linterrors', 'gitleaks', 'comments'
    ]
    
    # Check for missing columns
    missing_columns = [col for col in expected_columns if col not in df.columns]
    if missing_columns:
        return None, f"Missing required columns: {', '.join(missing_columns)}"
    
    # Clean data - handle NaN values and convert types
    processed_data = []
    for _, row in df.iterrows():
        item = {}
        
        # Process each column with proper type handling
        item['sl.no'] = str(row.get('sl.no', '')).strip()
        item['reponame'] = str(row.get('reponame', '')).strip()
        item['owner'] = str(row.get('owner', '')).strip()
        
        # Handle coverage
        coverage = row.get('coverage')
        if pd.isna(coverage):
            item['coverage'] = 0.0
        elif isinstance(coverage, str) and '%' in coverage:
            try:
                item['coverage'] = float(coverage.replace('%', '').strip())
            except:
                item['coverage'] = 0.0
        else:
            item['coverage'] = safe_float(coverage)
        
        # Handle other numeric columns
        item['linterrors'] = safe_int(row.get('linterrors'))
        item['gitleaks'] = safe_int(row.get('gitleaks'))
        
        # Handle gate status
        gate = row.get('gate')
        if pd.isna(gate):
            gate = 'fail'
        else:
            gate = str(gate).strip().lower()
        item['gate'] = 'pass' if gate == 'pass' else 'fail'
        
        # Handle PR URL
        pr_url = row.get('pr_url')
        if pd.isna(pr_url):
            item['pr_url'] = ''
        else:
            item['pr_url'] = str(pr_url).strip()
        
        # Handle other string columns
        item['mode'] = '' if pd.isna(row.get('mode')) else str(row.get('mode', '')).strip()
        
        # Handle date
        date_val = row.get('date')
        if pd.notna(date_val):
            try:
                item['date'] = pd.to_datetime(date_val).strftime('%Y-%m-%d')
            except:
                item['date'] = str(date_val)
        else:
            item['date'] = ''
        
        # Handle comments - convert NaN to empty string
        comments = row.get('comments')
        if pd.isna(comments):
            item['comments'] = ''
        else:
            item['comments'] = str(comments).strip()
        
        processed_data.append(item)
    
    return processed_data, None

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0

def safe_int(value):
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0

def generate_cve_table(grouped_data):
    try:
        html = """
        <div class="table-responsive">
        <table class="table table-hover table-bordered">
            <thead class="thead-dark">
                <tr>
                    <th>Image Name</th>
                    <th>Image Owner</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Total</th>
                    <th>Report URL</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for image_name, data in sorted(grouped_data.items()):
            counts = data
            total = sum([counts['Critical'], counts['High'], counts['Medium'], counts['Low']])
            
            report_urls_html = generate_report_urls_html(data.get('report_urls', set()))
            owners_html = generate_owners_html(data.get('image_owners', set()))
            
            html += f"""
            <tr>
                <td>{image_name}</td>
                <td class="owner-cell">{owners_html}</td>
                <td class="critical-count">{counts['Critical']}</td>
                <td class="high-count">{counts['High']}</td>
                <td class="medium-count">{counts['Medium']}</td>
                <td class="low-count">{counts['Low']}</td>
                <td class="total-count">{total}</td>
                <td class="report-url-cell">{report_urls_html}</td>
                <td>
                    <button onclick="toggleDetails('{image_name}')" 
                            class="btn btn-sm btn-primary details-btn">
                        Show Details
                    </button>
                </td>
            </tr>
            <tr id="details_{image_name}" class="details-row" style="display:none;">
                <td colspan="9">
                    <div class="severity-details">
                        <div class="severity-chart">
                            <div class="severity-circle critical">
                                <span>{counts['Critical']}</span>
                                <small>Critical</small>
                            </div>
                            <div class="severity-circle high">
                                <span>{counts['High']}</span>
                                <small>High</small>
                            </div>
                            <div class="severity-circle medium">
                                <span>{counts['Medium']}</span>
                                <small>Medium</small>
                            </div>
                            <div class="severity-circle low">
                                <span>{counts['Low']}</span>
                                <small>Low</small>
                            </div>
                        </div>
                        <div class="additional-details">
                            <div class="owners-container">
                                <h5>Image Owners:</h5>
                                {owners_html if owners_html else "No owners specified"}
                            </div>
                            <div class="report-urls-container">
                                <h5>Report Links:</h5>
                                {report_urls_html if report_urls_html else "No reports available"}
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        html += """
            </tbody>
        </table>
        </div>
        """
        return html
        
    except Exception as e:
        return f"<div class='alert alert-danger'>Error generating CVE table: {str(e)}</div>"

def generate_ut_table(data):
    try:
        html = """
        <div class="table-responsive">
        <table class="table table-hover table-bordered">
            <thead class="thead-dark">
                <tr>
                    <th>Sl.No</th>
                    <th>Repo Name</th>
                    <th>Owner</th>
                    <th>Coverage</th>
                    <th>Gate</th>
                    <th>PR URL</th>
                    <th>Mode</th>
                    <th>Date</th>
                    <th>Lint Errors</th>
                    <th>Git Leaks</th>
                    <th>Comments</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for row in data:
            # Format coverage with percentage
            coverage = f"{row.get('coverage', 0):.1f}%" if isinstance(row.get('coverage'), (int, float)) else "N/A"
            
            # Format PR URL as link
            pr_url = row.get('pr_url', '')
            pr_url_html = f'<a href="{pr_url}" target="_blank" class="report-link">View PR</a>' if pr_url else "N/A"
            
            # Get gate status
            gate_status = str(row.get('gate', '')).lower()
            
            html += f"""
            <tr>
                <td>{row.get('sl.no', '')}</td>
                <td>{row.get('reponame', '')}</td>
                <td>{row.get('owner', '')}</td>
                <td class="{'text-danger' if float(row.get('coverage', 0)) < 80 else 'text-success'}">{coverage}</td>
                <td class="{'text-success' if gate_status == 'pass' else 'text-danger'}">{gate_status.capitalize()}</td>
                <td>{pr_url_html}</td>
                <td>{row.get('mode', '')}</td>
                <td>{row.get('date', '')}</td>
                <td class="{'text-danger' if int(row.get('linterrors', 0)) > 0 else 'text-success'}">{row.get('linterrors', '')}</td>
                <td class="{'text-danger' if int(row.get('gitleaks', 0)) > 0 else 'text-success'}">{row.get('gitleaks', '')}</td>
                <td>{row.get('comments', '')}</td>
            </tr>
            """
        
        html += """
            </tbody>
        </table>
        </div>
        """
        return html
        
    except Exception as e:
        return f"<div class='alert alert-danger'>Error generating UT table: {str(e)}</div>"
def generate_report_urls_html(urls):
    if not urls:
        return "No report available"
    return "<br>".join(
        f'<a href="{url}" target="_blank" class="report-link">'
        '<i class="fas fa-external-link-alt"></i> View Report</a>'
        for url in urls if url
    )

def generate_owners_html(owners):
    if not owners:
        return "No owner specified"
    return ", ".join(owner for owner in owners if owner)

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    scan_type = request.args.get('scan_type', 'cve')
    data_type = request.args.get('data_type', 'master')
    table_html = ""
    error_message = None
    
    # Get the appropriate filename
    filename = SCAN_TYPES.get(scan_type, {}).get(data_type)
    if not filename:
        error_message = "Invalid scan type or data type"
    else:
        data, error = process_csv_data(filename, scan_type)
        if data:
            if scan_type == 'cve':
                table_html = generate_cve_table(data)
            else:
                table_html = generate_ut_table(data)
        else:
            error_message = error
    
    return render_template('dashboard.html', 
                         table_html=table_html,
                         scan_type=scan_type,
                         data_type=data_type,
                         error_message=error_message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
