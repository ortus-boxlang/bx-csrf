package ortus.boxlang.modules.csrf;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.runtime.scopes.Key;

public class IntegrationTest extends BaseIntegrationTest {

	@DisplayName("Test the module loads in BoxLang")
	@Test
	public void testModuleLoads() {
		// Verify things got registered
		assertThat(moduleService.getRegistry().containsKey(moduleName)).isTrue();
		assertThat(runtime.getSchedulerService().hasScheduler(Key.of("CSRFTokenReaper@csrf"))).isTrue();
		assertThat(runtime.getFunctionService().hasGlobalFunction("CSRFGenerateToken")).isTrue();
		assertThat(runtime.getFunctionService().hasGlobalFunction("CSRFVerifyToken")).isTrue();

		// @formatter:off
		// runtime.executeSource(
		//     """
		// 	// Testing code here
		// 	""",
		//     context
		// );
		// @formatter:on
	}
}
