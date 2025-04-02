from flask import Flask, render_template, request
import pandas as pd
import os
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

def process_csv_data(csv_file):
    try:
        # Verify file exists and is not empty
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

        # Standardize column names (case insensitive, strip whitespace)
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
        
        # Define required and optional columns
        required_columns = ['image_name', 'severity', 'count']
        optional_columns = ['report_url', 'image_owner']
        
        # Check required columns
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return None, f"Missing required columns: {', '.join(missing_columns)}"

        # Clean data - keep only needed columns
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
            
            # Collect report URLs if they exist
            if 'report_url' in row and pd.notna(row['report_url']):
                grouped_data[image_name]['report_urls'].add(str(row['report_url']).strip())
            
            # Collect image owners if they exist
            if 'image_owner' in row and pd.notna(row['image_owner']):
                grouped_data[image_name]['image_owners'].add(str(row['image_owner']).strip())
        
        return grouped_data, None

    except Exception as e:
        return None, f"Error processing CSV: {str(e)}"

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

def generate_html_table(grouped_data):
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
            
            # Generate optional fields HTML
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
        return f"<div class='alert alert-danger'>Error generating table: {str(e)}</div>"

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    active_tab = request.args.get('tab', 'cve')
    table_html = ""
    selected_file = "None"
    error_message = None
    
    if request.method == 'POST':
        try:
            if 'master' in request.form:
                selected_file = "master-output.csv"
                grouped_data, error = process_csv_data(selected_file)
                if grouped_data:
                    table_html = generate_html_table(grouped_data)
                else:
                    error_message = error
            elif 'feature' in request.form:
                selected_file = "output.csv"
                grouped_data, error = process_csv_data(selected_file)
                if grouped_data:
                    table_html = generate_html_table(grouped_data)
                else:
                    error_message = error
        except Exception as e:
            error_message = f"Unexpected error: {str(e)}"
    
    return render_template('dashboard.html', 
                         table_html=table_html,
                         selected_file=selected_file,
                         active_tab=active_tab,
                         error_message=error_message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
