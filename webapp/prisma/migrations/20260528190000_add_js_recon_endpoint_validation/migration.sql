ALTER TABLE "projects" ADD COLUMN "js_recon_validate_endpoints" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "js_recon_endpoint_accept_status" INTEGER[] DEFAULT ARRAY[200, 201, 204, 301, 302, 307, 308, 401, 403, 405]::INTEGER[];
ALTER TABLE "projects" ADD COLUMN "js_recon_endpoint_custom_headers" TEXT[] DEFAULT ARRAY[]::TEXT[];
