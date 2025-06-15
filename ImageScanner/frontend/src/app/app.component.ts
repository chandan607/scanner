import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatSelectModule } from '@angular/material/select';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatInputModule,
    MatButtonModule,
    MatProgressBarModule,
    MatTableModule,
    MatCardModule,
    MatSelectModule
  ],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title(title: any) {
    throw new Error('Method not implemented.');
  }
  imageName: string = '';
  result: any = null;
  error: string | null = null;
  loading: boolean = false;
  dataSource: any[] = [];
  selectedSeverity: string = 'ALL';
  sortDirection: 'asc' | 'desc' = 'desc';
  noVulnerability:boolean=false;

  constructor(private http: HttpClient) {}

  get filteredAndSortedData(): any[] {
    let data = [...this.dataSource];

   if (this.selectedSeverity !== 'ALL') {
      data = data.filter(item => item.Severity === this.selectedSeverity);
    }

    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];

    data.sort((a, b) => {
      const indexA = severityOrder.indexOf(a.Severity);
      const indexB = severityOrder.indexOf(b.Severity);

      const safeIndexA = indexA === -1 ? severityOrder.length : indexA;
      const safeIndexB = indexB === -1 ? severityOrder.length : indexB;

      return this.sortDirection === 'asc' ? safeIndexA - safeIndexB : safeIndexB - safeIndexA;
    });


    return data;
  }

  toggleSortDirection() {
    this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
  }

originalData: any[] = ["ALL"];    // Replace with actual structure
filteredData: any[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];

ngOnInit() {
  this.applyFilter();        // Initial load
}

applyFilter() {
  if (this.selectedSeverity === 'ALL') {
    this.filteredData = [...this.originalData];  // Show all
  } else {
    this.filteredData = this.originalData.filter(
      item => item.Severity === this.selectedSeverity
    );
  }
}

  scanImage() {
    this.loading = true;
    this.result = null;
    this.error = null;
    this.dataSource = [];

    this.http.post<any>('http://localhost:8000/scan', { image: this.imageName }).subscribe({
      next: (data) => {
        this.result = data;
        this.dataSource = data?.vulnerabilities || [];
        if(this.dataSource.length == 0)
        {
           this.noVulnerability=true;
        }
        this.loading = false;
      },
      error: (err) => {
        //this.error = String(err.error?.detail).includes("Scan failed");
        if(String(err.error?.detail).includes("Scan failed"))
        {
             this.error="Scan failed"
        }
        if(String(err.error?.detail).includes("unable to find the specified image"))
        {
             this.error="No Image Found"
        }

        this.loading = false;
        this.noVulnerability = false;
      }
    });
  }

  getSeverityStyle(severity: string): any {
    const baseStyle = {
      padding: '2px 6px',
      'border-radius': '4px',
      color: 'white',
      'font-weight': 'bold'
    };

    switch (severity.toLowerCase()) {
      case 'critical':
        return { ...baseStyle, background: '#d32f2f' };
      case 'high':
        return { ...baseStyle, background: '#f44336' };
      case 'medium':
        return { ...baseStyle, background: '#ff9800' };
      case 'low':
        return { ...baseStyle, background: '#4caf50' };
      default:
        return { ...baseStyle, background: '#757575' };
    }
  }

  downloadCSV() {
    if (!this.filteredAndSortedData?.length) return;

    const headers = ['ID', 'Package', 'InstalledVersion', 'FixedVersion', 'Severity', 'Title'];
    const csvRows = [
      headers.join(','),
      ...this.filteredAndSortedData.map(row =>
        headers.map(field => JSON.stringify(row[field] ?? '')).join(',')
      )
    ];

    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerabilities.csv';
    a.click();

    window.URL.revokeObjectURL(url);
  }
}
