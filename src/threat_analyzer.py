#!/usr/bin/env python
import pandas as pd
import requests
import zipfile
import io
import joblib
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from utils import extract_features


def load_datasets():
    """Loads the phishing and benign datasets."""
    # 1. Load the original phishing dataset
    print("Loading original phishing dataset...")
    phishing_data_url = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json"
    df_phishing = pd.read_json(phishing_data_url)
    print(f"Loaded {len(df_phishing)} samples from phishing dataset.")

    # 2. Load Tranco top sites list for benign URLs
    print("\nDownloading Tranco top sites list for data augmentation...")
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        response = requests.get(tranco_url)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open('top-1m.csv') as f:
                df_tranco = pd.read_csv(f, names=['rank', 'domain'])
        
        benign_urls = [f"https://www.{domain}" for domain in df_tranco['domain']]
        df_benign = pd.DataFrame({'text': benign_urls, 'label': 'benign'})
        print(f"Loaded {len(df_benign)} benign samples from Tranco list.")
        return df_phishing, df_benign
    except requests.exceptions.RequestException as e:
        print(f"Could not download Tranco list: {e}. Proceeding with phishing dataset only.")
        return df_phishing, pd.DataFrame()

def generate_targeted_samples():
    """Generates a large, diverse set of targeted benign samples for free hosting sites,
    including realistic benign paths and occasional query strings. Deterministic with seed=42."""
    import re
    
    print("\nGenerating a large set of targeted benign examples for free hosting sites...")

    random.seed(42)
    
    # Generate realistic personal and professional names
    first_names = ['john', 'jane', 'alex', 'sarah', 'mike', 'lisa', 'david', 'emma', 'chris', 'anna', 'mark', 'maria']
    last_names = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis', 'rodriguez', 'martinez']
    
    usernames = []
    # Personal name combinations
    for first in first_names:
        for last in last_names:
            usernames.extend([f"{first}{last}", f"{first}-{last}", f"{first}_{last}"])
    
    # Add common username patterns
    usernames.extend(['testuser', 'dev123', 'datasci', 'myproject', 'demouser', 'user2024', 
                     'developer', 'student', 'researcher', 'designer', 'coder', 'webdev'])
    
    project_names = ['portfolio', 'blog', 'website', 'api-docs', 'photo-gallery', 'resume', 'cv', 
                    'contact-form', 'simple-app', 'dev-log', 'personal-site', 'homepage', 'landing',
                    'docs', 'demo', 'showcase', 'projects', 'work', 'about', 'gallery', 'app']
    free_hosts = {
        'github.io': lambda u, p: f"https://{u}.github.io/{p}",
        'pythonanywhere.com': lambda u, p: f"https://{u}.pythonanywhere.com/",
        'weebly.com': lambda u, p: f"https://{p}-{u}.weebly.com/",
        'wixsite.com': lambda u, p: f"https://{u}.wixsite.com/{p}",
        'netlify.app': lambda u, p: f"https://{p}-{u}.netlify.app/",
        'vercel.app': lambda u, p: f"https://{p}-{u}.vercel.app/",
    }

    # Realistic benign paths and queries
    benign_paths_common = ['', '/', '/about', '/projects', '/resume', '/blog', '/docs', '/contact', '/cv', '/gallery']
    benign_paths_assets = ['/assets/app.css', '/static/js/app.js', '/images/logo.png', '/static/css/style.css']
    benign_sensitive_paths = ['/login', '/account', '/user/login']  # benign contexts where sensitive words may appear
    benign_queries = ['', '?lang=en', '?page=1', '?ref=home', '?utm_source=github', '?q=profile']

    def join_url(base: str, path: str, query: str) -> str:
        # Normalize slashes
        if path in ('', '/'):
            url = base if base.endswith('/') else base + '/'
        else:
            if path.startswith('/'):
                url = base.rstrip('/') + path
            else:
                url = base.rstrip('/') + '/' + path
        if query and not query.startswith('?'):
            url = url + '?' + query
        elif query:
            url = url + query
        return url

    benign_urls = [] 
    for _, url_format in free_hosts.items():
        for user in usernames:
            alpha_personal = bool(re.fullmatch(r'[a-z]{6,15}', user))
            for project in project_names:
                base_url = url_format(user, project)
                path = random.choice(benign_paths_common)
                if alpha_personal and random.random() < 0.05:
                    path = random.choice(benign_sensitive_paths)
                if random.random() < 0.05:
                    path = random.choice(benign_paths_assets)
                query = ''
                if random.random() < 0.30:
                    query = random.choice(benign_queries)
                final_url = join_url(base_url, path, query)
                benign_urls.append(final_url)

    df_benign_targeted = pd.DataFrame({'text': benign_urls, 'label': 'benign'})
    print(f"Generated {len(df_benign_targeted)} targeted benign samples to combat data bias.")
    return df_benign_targeted

def prepare_data(df_phishing, df_benign, df_targeted):
    """Combines, shuffles, and standardizes the datasets."""
    print("\nPreparing and cleaning data...")
    df = pd.concat([df_phishing, df_benign, df_targeted], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    label_map = {'benign': 0, 'phishing': 1, 0: 0, 1: 1}
    df['label'] = df['label'].map(label_map)
    df.dropna(subset=['label'], inplace=True)
    df['label'] = df['label'].astype(int)
    
    # print("Label standardization complete.")
    # print(df['label'].value_counts())
    # print(f"Total samples for training: {len(df)}")
    return df

def create_features(df):
    """Extracts features from the URL text."""
    print("\nExtracting features from URLs...")
    features_series = df['text'].apply(extract_features)
    features_df = pd.json_normalize(features_series)
    df_with_features = pd.concat([df, features_df], axis=1)
    print("Feature extraction complete.")
    return df_with_features

def train_and_evaluate(df):
    """Trains the model, evaluates its performance (including provider-slice FPR), and prints results."""
    print("\nStarting model training and evaluation...")
    X = df.drop(['label', 'text'], axis=1)
    y = df['label']
    X = X.fillna(0)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    # print(f"Training data shape: {X_train.shape}")
    # print(f"Testing data shape: {X_test.shape}")
    
    # Tuned RandomForest for better generalization
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print("Model training complete.")
    
    print("\nEvaluating model performance...")
    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Phishing']))
    
    print("\nTop 10 Feature Importances:")
    feature_importances = pd.DataFrame(model.feature_importances_, index=X_train.columns, columns=['importance']).sort_values('importance', ascending=False)
    # print(feature_importances.head(10))
    # # Save full importances to CSV
    # try:
    #     fi_out = feature_importances.reset_index().rename(columns={'index': 'feature'})
    #     fi_out.to_csv('feature_importances.csv', index=False)
    #     print("Saved feature importances to feature_importances.csv")
    # except Exception as e:
    #     print(f"[Warn] Could not save feature importances CSV: {e}")

    # Provider-slice evaluation (False Positive Rate per provider on the test set)
    try:
        texts_test = df.loc[X_test.index, 'text']
        y_pred_series = pd.Series(y_pred, index=X_test.index)
        providers = ['pythonanywhere.com', 'github.io', 'wixsite.com', 'weebly.com', 'netlify.app', 'vercel.app']
        print("\nProvider-slice False Positive Rate (FPR):")
        results = []
        for prov in providers:
            mask = texts_test.str.contains(prov, na=False)
            if mask.any():
                idx = texts_test[mask].index
                y_true_slice = y_test.loc[idx]
                y_pred_slice = y_pred_series.loc[idx]
                is_negative = (y_true_slice == 'benign') | (y_true_slice == 0)
                is_pred_positive = (y_pred_slice == 'phishing') | (y_pred_slice == 1)
                negatives = is_negative.sum()
                fp = (is_pred_positive & is_negative).sum()
                fpr = (fp / negatives) if negatives > 0 else float('nan')
                print(f"  {prov:20s} count={len(idx):6d}  FPR={fpr:.4f}")
                results.append({'provider': prov, 'count': int(len(idx)), 'negatives': int(negatives), 'fp': int(fp), 'fpr': float(fpr) if fpr == fpr else ''})
        # # Save provider FPRs
        # if results:
        #     try:
        #         pd.DataFrame(results).to_csv('provider_fpr.csv', index=False)
        #         print("Saved provider-slice FPR to provider_fpr.csv")
        #     except Exception as e:
        #         print(f"[Warn] Could not save provider FPR CSV: {e}")
    except Exception as e:
        print(f"[Slice Eval] Skipped provider-slice evaluation due to error: {e}")
    
    return model, list(X.columns)

def save_model_and_features(model, features):
    """Saves the trained model and feature list to disk."""
    model_filename = 'phishing_model.joblib'
    features_filename = 'model_features.joblib'
    print(f"\nSaving model to {model_filename}...")
    joblib.dump(model, model_filename)
    print(f"Saving feature list to {features_filename}...")
    joblib.dump(features, features_filename)
    print("Model and features saved successfully.")

def main():
    """Main function to run the training pipeline."""
    df_phishing, df_benign = load_datasets()
    df_targeted = generate_targeted_samples()
    df_prepared = prepare_data(df_phishing, df_benign, df_targeted)
    df_featured = create_features(df_prepared)
    model, features = train_and_evaluate(df_featured)
    save_model_and_features(model, features)

if __name__ == "__main__":
    main()