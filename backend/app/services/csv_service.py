import csv
import io
from typing import Any, Dict, List


class CSVExportService:
    @staticmethod
    def export_report_csv(report_type: str, records: List[Dict[str, Any]]) -> str:
        """
        Exports domain records to RFC 4180 compliant CSV format.
        """
        output = io.StringIO()
        if not records:
            writer = csv.writer(output)
            writer.writerow(["Message", "Generated At"])
            writer.writerow(["No telemetry records found for selected filters", ""])
            return output.getvalue()

        # Extract field headers dynamically while maintaining deterministic ordering
        headers = list(records[0].keys())
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()

        for row in records:
            # Flatten any nested lists or dicts for clean CSV presentation
            clean_row = {}
            for k, v in row.items():
                if isinstance(v, (list, dict)):
                    clean_row[k] = str(v)
                else:
                    clean_row[k] = v
            writer.writerow(clean_row)

        return output.getvalue()
