import base64
from xml.sax.saxutils import unescape
import xmltodict
import tkinter as tk
from tkinter import scrolledtext, messagebox


def parse_saml_response(saml_response):
    """
    Parses a base64-encoded SAML Response and supports both SAML 1.1 and SAML 2.0.
    :param saml_response: Base64-encoded SAML response (str)
    :return: Parsed human-readable data (str)
    """
    try:
        # Decode the base64-encoded SAML Response
        decoded_response = base64.b64decode(saml_response)
        decoded_xml = decoded_response.decode('utf-8')

        # Optionally, clean up HTML encoding issues
        decoded_xml = unescape(decoded_xml)

        # Parse the XML
        saml_dict = xmltodict.parse(decoded_xml)

        # Check for SAML version by examining the namespace
        if 'urn:oasis:names:tc:SAML:2.0:assertion' in decoded_xml:
            # SAML 2.0 Parsing
            attributes = []
            assertions = saml_dict.get('samlp:Response', {}).get('saml:Assertion', {})
            attr_elements = assertions.get('saml:AttributeStatement', {}).get('saml:Attribute', [])
            if not isinstance(attr_elements, list):
                attr_elements = [attr_elements]  # Ensure it's a list for uniformity
            for attr in attr_elements:
                if attr:
                    attr_name = attr.get('@Name', 'Unknown Attribute')
                    attr_values = attr.get('saml:AttributeValue', 'No Value')
                    if isinstance(attr_values, list):
                        attr_values = ', '.join(attr_values)
                    attributes.append(f"{attr_name}: {attr_values}")

            result = "Decoded XML:\n" + decoded_xml + "\n\nExtracted Attributes:\n" + "\n".join(attributes)

        elif 'urn:oasis:names:tc:SAML:1.1:assertion' in decoded_xml:
            # SAML 1.1 Parsing
            attributes = []
            assertions = saml_dict.get('saml:Assertion', {})
            attr_elements = assertions.get('saml:AttributeStatement', {}).get('saml12:Attribute', [])
            if not isinstance(attr_elements, list):
                attr_elements = [attr_elements]
            for attr in attr_elements:
                if attr:
                    attr_name = attr.get('@AttributeName', 'Unknown Attribute')
                    attr_values = attr.get('saml12:AttributeValue', 'No Value')
                    if isinstance(attr_values, list):
                        attr_values = ', '.join(attr_values)
                    attributes.append(f"{attr_name}: {attr_values}")

            result = "Decoded XML:\n" + decoded_xml + "\n\nExtracted Attributes:\n" + "\n".join(attributes)
        else:
            result = "Unable to determine SAML version or unsupported format."

        return result
    except Exception as e:
        return f"Error parsing SAML Response: {e}"


def on_parse_button_click():
    """
    Handles the Parse button click event to process the SAML response.
    """
    saml_response = saml_input.get("1.0", tk.END).strip()
    if not saml_response:
        messagebox.showerror("Error", "Please paste a SAML response to parse.")
        return

    # Parse the response
    parsed_result = parse_saml_response(saml_response)

    # Display the result
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, parsed_result)


# Set up the GUI
root = tk.Tk()
root.title("SAML Response Parser")
root.geometry("800x600")

# Input Label
input_label = tk.Label(root, text="Paste Base64-Encoded SAML Response Below:")
input_label.pack(anchor="w", padx=10, pady=5)

# SAML Input
saml_input = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=10, font=("Arial", 12))
saml_input.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

# Parse Button
parse_button = tk.Button(root, text="Parse SAML Response", command=on_parse_button_click)
parse_button.pack(pady=10)

# Output Label
output_label = tk.Label(root, text="Parsed Output:")
output_label.pack(anchor="w", padx=10, pady=5)

# Result Output
result_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, font=("Courier", 10))
result_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

# Run the GUI
root.mainloop()
