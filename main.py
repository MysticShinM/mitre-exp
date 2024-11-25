import os
import pandas as pd
import yaml


def process_yaml_files(folder_path, output_excel='yaml_files_with_content.xlsx'):
    """
    Search for all .yaml and .yml files in a folder, extract their content, and save it to an Excel file.

    :param folder_path: Path of the folder to search
    :param output_excel: Default path to save the Excel file
    """
    all_data = []

    # Walk through the folder and subfolders
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(('.yml', '.yaml')):  # Check for both .yml and .yaml extensions
                file_path = os.path.join(root, file)

                # Read the .yaml or .yml file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        yaml_content = yaml.safe_load(f)

                    if isinstance(yaml_content, dict):  # If it's a dictionary, process it
                        for key, value in yaml_content.items():
                            all_data.append({
                                'File Name': file,
                                'File Path': os.path.relpath(file_path, folder_path),
                                'Key': key,
                                'Value': value
                            })
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    continue

    # Create a DataFrame
    if all_data:
        df = pd.DataFrame(all_data)
        # Pivot table to show keys as columns and rows for each file
        pivot_table = df.pivot(index=['File Name', 'File Path'], columns='Key', values='Value')
        pivot_table.reset_index(inplace=True)

        # Save to Excel
        pivot_table.to_excel(output_excel, index=False)
        print(f"Excel file saved to {output_excel}")
    else:
        print("No .yaml or .yml files with valid content found in the specified folder or its subfolders.")


# Get folder path from user
folder_to_search = input("Enter the folder path to search for .yaml/.yml files: ").strip()

# Call the function
process_yaml_files(folder_to_search)
