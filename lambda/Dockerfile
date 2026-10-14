FROM ghcr.io/anchore/syft:latest AS syft
FROM public.ecr.aws/lambda/python:3.12
COPY --from=syft /syft /usr/local/bin/syft
RUN pip install --no-cache-dir scikit-learn==1.6.1 joblib
COPY app.py sbom.py handler.py cve_model.joblib sbom_model.joblib nvd_features.csv.gz ${LAMBDA_TASK_ROOT}/
CMD ["handler.lambda_handler"]
